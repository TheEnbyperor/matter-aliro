# Matter Aliro Lock

A Python implementation of the Matter smart-home protocol, and the Matter side of an Aliro lock implemented with that.

Note, this project is currently missing a few crucial elements:

- Access Control is not implemented. Anyone with the pairing passcode or a certificate issued under an installed fabric 
    root gets full administrator privileges to execute anything.
- The General Diagnostics cluster is not implemented
- The Administrator Commissioning cluster is not implemented. This means it is impossible to generate a new pairing 
    passcode to add the device to a second fabric.
- Group Sessions and the Group Key Management cluster are not implemented.
- The NFC half of Aliro is not implemented. The lock device simply saves received public keys to disk, and does nothing
    with them.