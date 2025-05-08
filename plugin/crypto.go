package plugin

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// Functions that deals with the encryption/decryption of the filekey we get from age

// Currently the sender does not utilize the TPM for any crypto operations,
// but the decryption of the filekey for the identity itself does.

const p256Label = "age-encryption.org/v1/tpm-p256"

// Key Dreivative function for age-plugin-tpm
// Sets up a hkdf instance with a salt that contains the shared key and the public key
// Returns an chacha20poly1305 AEAD instance
func kdf(sharedKey, publicKey *ecdh.PublicKey, shared []byte) (cipher.AEAD, error) {
	sharedKeyB := sharedKey.Bytes()
	publicKeyB := publicKey.Bytes()

	// We use the concatinated bytes of the shared key and the public key for the
	// key derivative functions.
	salt := make([]byte, 0, len(sharedKeyB)+len(publicKeyB))
	salt = append(salt, sharedKeyB...)
	salt = append(salt, publicKeyB...)

	h := hkdf.New(sha256.New, shared, salt, []byte(p256Label))
	wrappingKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, wrappingKey); err != nil {
		return nil, err
	}

	return chacha20poly1305.New(wrappingKey)
}

// Unwraps a key using the standard kdf function.
func UnwrapKey(sessionKey, publicKey *ecdh.PublicKey, shared, fileKey []byte) ([]byte, error) {
	nonce := make([]byte, chacha20poly1305.NonceSize)

	aead, err := kdf(sessionKey, publicKey, shared)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, fileKey, nil)
}

// Wraps a key using the standard kdf function.
func WrapKey(sessionKey, publicKey *ecdh.PublicKey, shared, fileKey []byte) ([]byte, error) {
	nonce := make([]byte, chacha20poly1305.NonceSize)

	aead, err := kdf(sessionKey, publicKey, shared)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, fileKey, nil), nil
}

// Wraps the file key in a session key
// Returns the sealed filekey, the session pubkey bytes, error
func EncryptFileKey(fileKey []byte, pubkey *ecdh.PublicKey) ([]byte, []byte, error) {

	// Create the session key we'll be passing to the stanza
	sessionKey, _ := ecdh.P256().GenerateKey(rand.Reader)
	sessionPubKey := sessionKey.PublicKey()

	// Do ECDH for the shared secret
	shared, err := sessionKey.ECDH(pubkey)
	if err != nil {
		return nil, nil, err
	}

	// Wrap the filekey with our aead instance
	b, err := WrapKey(sessionPubKey, pubkey, shared, fileKey)
	if err != nil {
		return nil, nil, err
	}

	// Return the bytes, and the marshalled compressed bytes of the session public
	// key.
	return b, MarshalCompressedEC(sessionPubKey), nil
}

// Decrypts and unwraps a filekey
func DecryptFileKeyTPM(tpm transport.TPMCloser, identity *Identity, remoteKey, fileKey, pin []byte) ([]byte, error) {
	if Log != nil {
		Log.Println("[DEBUG] Starting DecryptFileKeyTPM function")
		Log.Printf("[DEBUG] Remote key length: %d", len(remoteKey))
		Log.Printf("[DEBUG] File key length: %d", len(fileKey))
		Log.Printf("[DEBUG] PIN provided: %t", len(pin) > 0)
	}
	
	// Unmarshal the compressed ECDH session key we got from the stanza
	x, y, sessionKey, err := UnmarshalCompressedEC(remoteKey)
	if err != nil {
		if Log != nil {
			Log.Printf("[ERROR] Failed to unmarshal EC key: %v", err)
		}
		return nil, err
	}
	
	if Log != nil {
		Log.Printf("[DEBUG] EC point X: %s", x.Text(16))
		Log.Printf("[DEBUG] EC point Y: %s", y.Text(16))
	}
	
	// Validate that the point is on the curve
	if !elliptic.P256().IsOnCurve(x, y) {
		if Log != nil {
			Log.Println("[ERROR] Point is not on P-256 curve")
		}
		return nil, fmt.Errorf("point is not on P-256 curve")
	}

	// We'll be using the SRK for the session encryption, and we need it as the
	// parent for our application key. Make sure it's created and available.
	if Log != nil {
		Log.Println("[DEBUG] Creating SRK for session encryption")
	}
	srkHandle, srkPublic, err := CreateSRK(tpm)
	if err != nil {
		if Log != nil {
			Log.Printf("[ERROR] Failed to create SRK: %v", err)
		}
		return nil, err
	}
	if Log != nil {
		Log.Printf("[DEBUG] SRK handle created: 0x%X", srkHandle.HandleValue())
	}
	defer FlushHandle(tpm, srkHandle)

	// We load the identity into the TPM, using the SRK parent.
	if Log != nil {
		Log.Println("[DEBUG] Loading identity with SRK parent")
	}
	handle, err := LoadIdentityWithParent(tpm, *srkHandle, identity)
	if err != nil {
		if Log != nil {
			Log.Printf("[ERROR] Failed to load identity with parent: %v", err)
		}
		return nil, err
	}
	if Log != nil {
		Log.Printf("[DEBUG] Identity loaded with handle: 0x%X", handle.HandleValue())
	}
	defer FlushHandle(tpm, handle.Handle)

	// Add the AuthSession for the handle
	Log.Printf("[DEBUG] Setting auth for handle with PIN length: %d", len(pin))
	handle.Auth = tpm2.PasswordAuth(pin)

	// Ensure proper buffer sizes for coordinates - try different padding approaches
	Log.Println("[DEBUG] Preparing EC point coordinates for TPM")
	
	// Approach 1: Right-padded, fixed-size coordinates
	xBytes := make([]byte, 32)
	yBytes := make([]byte, 32)
	x.FillBytes(xBytes)
	y.FillBytes(yBytes)
	Log.Printf("[DEBUG] Prepared 32-byte right-padded coordinates for TPM")
	
	// ECDHZGen command for the TPM, turns the sesion key into something we understand.
	if Log != nil {
		Log.Println("[DEBUG] Creating ECDHZGen command")
	}
	ecdh := tpm2.ECDHZGen{
		KeyHandle: *handle,
		InPoint: tpm2.New2B(
			tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{Buffer: xBytes},
				Y: tpm2.TPM2BECCParameter{Buffer: yBytes},
			},
			),
		}
		if Log != nil {
			Log.Println("[DEBUG] ECDHZGen command created")
		}

	// Execute the ECDHZGen command, we also add session encryption.
	// In this case the session encryption only encrypts the private part going out of the TPM, which is the shared
	// session key we are using in our kdf.
	if Log != nil {
		Log.Println("[DEBUG] Executing ECDHZGen command with no session first")
	}
	// Try several different session configurations to address potential TPM compatibility issues
	var ecdhRsp *tpm2.ECDHZGenResponse
	var attempts []string
	var errors []error
	
	// Attempt 1: No session (simplest case)
	Log.Println("[DEBUG] Attempt 1: Executing ECDHZGen with no session")
	ecdhRsp, err = ecdh.Execute(tpm)
	attempts = append(attempts, "No session")
	errors = append(errors, err)
	
	// Attempt 2: Basic HMAC session without encryption or salting
	if err != nil {
		Log.Printf("[DEBUG] Attempt 1 failed: %v", err)
		Log.Println("[DEBUG] Attempt 2: Trying with basic HMAC session")
		ecdhRsp, err = ecdh.Execute(tpm, tpm2.HMAC(tpm2.TPMAlgSHA256, 16))
		attempts = append(attempts, "Basic HMAC")
		errors = append(errors, err)
	}
	
	// Attempt 3: Original complex session
	if err != nil {
		Log.Printf("[DEBUG] Attempt 2 failed: %v", err)
		Log.Println("[DEBUG] Attempt 3: Trying with original session parameters")
		
		Log.Println("[DEBUG] Creating HMAC session with encryption parameters")
		sessionParams := tpm2.HMAC(tpm2.TPMAlgSHA256, 16,
			tpm2.AESEncryption(128, tpm2.EncryptOut),
			tpm2.Salted(srkHandle.Handle, *srkPublic))
		
		if Log != nil {
			Log.Println("[DEBUG] Executing ECDHZGen with full session parameters")
		}
		ecdhRsp, err = ecdh.Execute(tpm, sessionParams)
		attempts = append(attempts, "Full HMAC with encryption")
		errors = append(errors, err)
	}
	
	// Attempt 4: Try with a session with different encryption parameters
	if err != nil {
		Log.Printf("[DEBUG] Attempt 3 failed: %v", err)
		Log.Println("[DEBUG] Attempt 4: Trying with different encryption parameters")
		
		sessionParams := tpm2.HMAC(tpm2.TPMAlgSHA256, 16,
			tpm2.AESEncryption(128, tpm2.EncryptIn), // Change to EncryptIn
			tpm2.Salted(srkHandle.Handle, *srkPublic))
		
		ecdhRsp, err = ecdh.Execute(tpm, sessionParams)
		attempts = append(attempts, "HMAC with EncryptIn")
		errors = append(errors, err)
	}
	if err != nil {
		// Provide more details on the error to help debug TPM issues
		Log.Printf("[ERROR] All ECDHZGen attempts failed")
		
		// Create a detailed error report of all attempts
		var errorMsg strings.Builder
		errorMsg.WriteString("TPM ECDH operation failed with all attempted methods:\n")
		for i, attempt := range attempts {
			if i < len(errors) && errors[i] != nil {
				errorMsg.WriteString(fmt.Sprintf("- Method %d (%s): %v\n", i+1, attempt, errors[i]))
			}
		}
		
		if strings.Contains(err.Error(), "TPM_RC_VALUE") {
			Log.Println("[DEBUG] TPM_RC_VALUE error detected - likely parameter mismatch")
			errorMsg.WriteString("\nThis appears to be a parameter value error, which could indicate:\n")
			errorMsg.WriteString("- The EC point coordinates may not be properly formatted for your TPM\n")
			errorMsg.WriteString("- There may be a TPM firmware compatibility issue\n")
			errorMsg.WriteString("- The session encryption parameters may be incompatible with your TPM\n")
			return nil, fmt.Errorf("failed ecdhzgen due to invalid parameter values: %v\n\nDetails: %s", 
				err, errorMsg.String())
		}
		
		return nil, fmt.Errorf("failed ecdhzgen: %v\n\nDetails: %s", err, errorMsg.String())
	}
	
	if Log != nil {
		Log.Println("[DEBUG] ECDHZGen executed successfully")
	}

	shared, err := ecdhRsp.OutPoint.Contents()
	if err != nil {
		if Log != nil {
			Log.Printf("[ERROR] Failed to get ECDH point contents: %v", err)
		}
		return nil, fmt.Errorf("failed getting ecdh point: %v", err)
	}
	if Log != nil {
		Log.Println("[DEBUG] Successfully extracted shared secret from TPM")
	}

	resp, err := identity.Recipient()
	if err != nil {
		if Log != nil {
			Log.Printf("[ERROR] Failed to get recipient from identity: %v", err)
		}
		return nil, err
	}
	if Log != nil {
		Log.Println("[DEBUG] Retrieved recipient from identity")
	}

	// Unwrap the key with the kdf/chacha20
	if Log != nil {
		Log.Println("[DEBUG] Unwrapping key with KDF")
		Log.Printf("[DEBUG] Session key length: %d bytes", len(sessionKey.Bytes()))
		Log.Printf("[DEBUG] Shared secret length: %d bytes", len(shared.X.Buffer))
	}
	
	b, err := UnwrapKey(sessionKey, resp.Pubkey, shared.X.Buffer, fileKey)
	if err != nil {
		if Log != nil {
			Log.Printf("[ERROR] Failed to unwrap key: %v", err)
		}
		return nil, err
	}
	if Log != nil {
		Log.Printf("[DEBUG] Successfully unwrapped key, length: %d bytes", len(b))
	}
	return b, nil
}

// Unmarshal a compressed ec key
func UnmarshalCompressedEC(b []byte) (*big.Int, *big.Int, *ecdh.PublicKey, error) {
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), b)
	ec := ecdsa.PublicKey{
		Curve: elliptic.P256(), X: x, Y: y,
	}
	key, err := ec.ECDH()
	return x, y, key, err
}

// Marshal a compressed EC key
func MarshalCompressedEC(pk *ecdh.PublicKey) []byte {
	x, y := elliptic.Unmarshal(elliptic.P256(), pk.Bytes())
	return elliptic.MarshalCompressed(elliptic.P256(), x, y)
}
