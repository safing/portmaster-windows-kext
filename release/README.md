# Releasing

This directory holds everything to go through the Microsoft signing procedure.  
You need an EV certificate.  
Get one here: https://docs.microsoft.com/en-us/windows-hardware/drivers/dashboard/get-a-code-signing-certificate  
(Important: certificate may be cheaper if you buy them through the above link)

### Prepare

- Compile the driver. See main README.
- You need:
  - `makecab`
  - `signtool` from Win SDK 8.1 or newer (for the `remove` command)

### Pre-Packaging

- Run `release_prepackage.bat` to:
  - copy all the needed files
  - remove existing signatures (we want the Microsoft signature to be the primary one for max. compatibility)
  - package everything for signing by Microsoft
  - calls `release_set_metadata.bat`, which you can create to set extra file version and metadata.

- Verify that the `PortmasterKext` dir looks like this:

        PortmasterKext
        └── amd64
            ├── PortmasterKext64.dll
            ├── PortmasterKext64.inf
            ├── PortmasterKext64.pdb
            └── PortmasterKext64.sys

- Sign the `.cab` file with your EV Code Signing Cert

### Let Microsoft Sign

- Go to https://partner.microsoft.com/en-us/dashboard/hardware/driver/New
- Enter "PortmasterKext" as the product name
- Upload `PortmasterKext.cab`
- Select the Windows 10 versions that you compiled and tested on
- Wait for the process to finish, download the `.zip`, extract it and rename to folder from `Signed_xxx` to `Signed`.

### Finalize and Add Own Signatures

- Run `release_finalize.bat` to:
  - copy the signed `.dll` and `.sys` to the Portmaster dist directory
- Sign the `.dll` and `.sys` files with your EV Code Signing Cert (for additional transparency) [Optional]

# Relevant Documentation

The available options for signing drivers for multiple Windows versions is here:  
https://docs.microsoft.com/en-gb/windows-hardware/drivers/dashboard/get-drivers-signed-by-microsoft-for-multiple-windows-versions

What they do not mention, is that `Universal` drivers will work on more Windows versions. The above process uses `attestation signing`, but still works on Win7, Win8.1 and Win10.
