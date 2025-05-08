package plugin

import (
	"bytes"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

const (
	PluginName = "tpm"
)

// Creates a Storage Key, or return the loaded storage key
func CreateSRK(tpm transport.TPMCloser) (*tpm2.AuthHandle, *tpm2.TPMTPublic, error) {
	// Check if Log is initialized to avoid nil pointer dereference
	if Log != nil {
		Log.Println("[DEBUG] Creating Storage Root Key (SRK)")
	}
	
	srk := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: []byte(nil),
				},
			},
		},
		InPublic: tpm2.New2B(tpm2.ECCSRKTemplate),
	}
	if Log != nil {
		Log.Println("[DEBUG] Configured SRK with ECC template")
	}

	var rsp *tpm2.CreatePrimaryResponse
	if Log != nil {
		Log.Println("[DEBUG] Executing CreatePrimary command")
	}
	rsp, err := srk.Execute(tpm)
	if err != nil {
		if Log != nil {
			Log.Printf("[ERROR] Failed to create SRK: %v", err)
		}
		return nil, nil, fmt.Errorf("failed creating primary key: %v", err)
	}
	if Log != nil {
		Log.Printf("[DEBUG] SRK created successfully, handle: 0x%X", rsp.ObjectHandle)
	}

	if Log != nil {
		Log.Println("[DEBUG] Getting SRK public contents")
	}
	srkPublic, err := rsp.OutPublic.Contents()
	if err != nil {
		if Log != nil {
			Log.Printf("[ERROR] Failed to get SRK public content: %v", err)
		}
		return nil, nil, fmt.Errorf("failed getting srk public content: %v", err)
	}
	if Log != nil {
		Log.Printf("[DEBUG] SRK public key type: %v", srkPublic.Type)
	}

	if Log != nil {
		Log.Println("[DEBUG] Creating auth handle for SRK")
	}
	return &tpm2.AuthHandle{
		Handle: rsp.ObjectHandle,
		Name:   rsp.Name,
		Auth:   tpm2.PasswordAuth(nil),
	}, srkPublic, nil
}

// Creates a new identity. It initializes a new SRK parent in the TPM and
// returns the identity and the corresponding recipient.
// Note: It does not load the identity key into the TPM.
func CreateIdentity(tpm transport.TPMCloser, pin []byte) (*Identity, *Recipient, error) {
	srkHandle, srkPublic, err := CreateSRK(tpm)
	if err != nil {
		return nil, nil, fmt.Errorf("failed creating SRK: %v", err)
	}

	defer FlushHandle(tpm, srkHandle)

	eccKey := tpm2.Create{
		ParentHandle: srkHandle,
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgECC,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
				Decrypt:             true,
			},
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgECC,
				&tpm2.TPMSECCParms{
					CurveID: tpm2.TPMECCNistP256,
					Scheme: tpm2.TPMTECCScheme{
						Scheme: tpm2.TPMAlgECDH,
						Details: tpm2.NewTPMUAsymScheme(
							tpm2.TPMAlgECDH,
							&tpm2.TPMSKeySchemeECDH{
								HashAlg: tpm2.TPMAlgSHA256,
							},
						),
					},
				},
			),
		}),
	}

	pinstatus := NoPIN

	if !bytes.Equal(pin, []byte("")) {
		eccKey.InSensitive = tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: pin,
				},
			},
		}
		pinstatus = HasPIN
	}

	var eccRsp *tpm2.CreateResponse
	eccRsp, err = eccKey.Execute(tpm,
		tpm2.HMAC(tpm2.TPMAlgSHA256, 16,
			tpm2.AESEncryption(128, tpm2.EncryptIn),
			tpm2.Salted(srkHandle.Handle, *srkPublic)))
	if err != nil {
		return nil, nil, fmt.Errorf("failed creating TPM key: %v", err)
	}

	identity := &Identity{
		Version: 1,
		PIN:     pinstatus,
		Private: eccRsp.OutPrivate,
		Public:  eccRsp.OutPublic,
	}

	recipient, err := identity.Recipient()
	if err != nil {
		return nil, nil, fmt.Errorf("failed getting recipient: %v", err)
	}
	return identity, recipient, nil
}

func LoadIdentity(tpm transport.TPMCloser, identity *Identity) (*tpm2.AuthHandle, error) {
	srkHandle, _, err := CreateSRK(tpm)
	if err != nil {
		return nil, err
	}

	defer FlushHandle(tpm, srkHandle)

	return LoadIdentityWithParent(tpm, *srkHandle, identity)
}

func LoadIdentityWithParent(tpm transport.TPMCloser, parent tpm2.AuthHandle, identity *Identity) (*tpm2.AuthHandle, error) {
	if Log != nil {
		Log.Println("[DEBUG] Loading identity with parent")
		Log.Printf("[DEBUG] Parent handle value: 0x%X", parent.Handle)
		Log.Printf("[DEBUG] Identity version: %d, PIN status: %s", identity.Version, identity.PIN.String())
	}
	
	loadBlobCmd := tpm2.Load{
		ParentHandle: parent,
		InPrivate:    identity.Private,
		InPublic:     identity.Public,
	}
	if Log != nil {
		Log.Println("[DEBUG] Executing tpm2.Load command")
	}
	loadBlobRsp, err := loadBlobCmd.Execute(tpm)
	if err != nil {
		if Log != nil {
			Log.Printf("[ERROR] Failed to load identity: %v", err)
		}
		return nil, fmt.Errorf("failed getting handle: %v", err)
	}
	if Log != nil {
		Log.Printf("[DEBUG] Successfully loaded identity, handle: 0x%X", loadBlobRsp.ObjectHandle)
		Log.Println("[DEBUG] Creating auth handle with nil password")
	}

	// Return a AuthHandle with a nil PasswordAuth
	return &tpm2.AuthHandle{
		Handle: loadBlobRsp.ObjectHandle,
		Name:   loadBlobRsp.Name,
		Auth:   tpm2.PasswordAuth(nil),
	}, nil
}
