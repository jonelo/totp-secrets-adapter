# TOTP Secrets Adapter

## What the project is for

The **TOTP Secrets Adapter** is a short script written entirely in Python to help you to setup an authenticator environment on your (trusted) personal computer (notebook, laptop, desktop) to generate the same time-based one-time passwords (TOTP) as the authenticator on your smartphone does. Actually it

- reads exported TOTP secrets 
- stores those TOTP secrets secretly by calling the interface of a target authenticator
- saves time, is less error-prone and more secure, as no manual copying/pasting of secrets is required

Supported TOTP secrets exctractors and supported authenticators are listed in section Software.

### Architecture

![totpsa](https://github.com/user-attachments/assets/92f8b39d-21d5-4326-8a21-277858a0079c)


### Description of the architecture

With the Google Authenticator app on your smartphone you can gather time-based one-time passwords (TOTP) secrets from two-factor authentication (2FA) servers.
On User's request, the Google Authenticator takes the gathered secrets and the current time and calculates short-lived TOTP which are shown to the User. Goolge Authenticator generates 6 digit codes.
The User can read the codes with the user's eyes and enter those codes to authenticate with the 2FA server.

In order to generate those TOTPs not only by your smartphone, but also with your (trusted) computer, you have to export the secrets.
This can be done by using the [extract_otp_secrets](https://github.com/scito/extract_otp_secrets) program which reads the exported QR codes from Google Authenticator by the camera and stores those as .json files.
The .json files are being read by the *TOTP secrets adapter* (this project) which calls the CLI of the [authenticator cli](https://github.com/JeNeSuisPasDave/authenticator). The authenticator cli stores the secrets to an encrypted file called authenticator.data, and the authenticator cli can then produce the same TOTP on your computer as the Google Authenticator on your smartphone does.

## What are the requirements?

### Hardware

- any hardware that can run Python programs

### Software

#### Operating System

- Microsoft Windows, macOS, or GNU/Linux

#### Required Software

- an authenticator app on your smartphone that can export TOTP secrets (e.g. Google Authenticator)
- a supported TOTP secret extractor
- a supported target authenticator
- Pyhton
- the TOTP secrets adapter


#### What TOTP tools/export formats are supported?

| TOTP Extractor                                                               | Written in | License | Supported interfaces for the export |
|------------------------------------------------------------------------------|------------|---------|-------------------------------------|
| [Roland's extract_otp_secrets](https://github.com/scito/extract_otp_secrets) | Python     | GPLv3   | JSON                                |

#### What target authenticators are supported?

| Authenticator                                                               | Written in | License | Supported interfaces for the import |  
|-----------------------------------------------------------------------------|------------|---------|-------------------------------------|
| [Dave's authenticator](https://github.com/JeNeSuisPasDave/authenticator)    | Pyhton     | MIT     | CLI + stdin                         |


## How to install, export, import and use it?

### Installation

#### Python

To run the script you need Python. You can get it from https://phyton.org

#### Roland's extract_otp_secrets 

In order to get input data for the totp-secretes-adapter script, you need to export the TOTP secrets.
This can be done by the [extract_otp_secrets](https://github.com/scito/extract_otp_secrets) program.

#### Dave's authenticator

If you want an authenticator with a CLI running on your computer, go to [Dave's authenticator](https://github.com/JeNeSuisPasDave/authenticator) and follow the instructions there for installation. It is very easy ...

```
> pip install authenticator
```

#### Johann's totp-secrets-adapter

Go to the [releases section](), and download the script. To test it, run it by entering ...

```
> python ./totpsa.py
Usage: ./totpsa.py [json file]...
```


### Export of the TOTP secrets

#### Save all your 2FA-accounts to Google Authenticator

Google Authenticator can export the TOTP secrets.
   
#### Export the TOTP secrets to .json files

- Open the extract_otp_secrets app
- Open the Google Authenticator app on your smartphone
  - Select export accounts from the Hamburger menu
  - Generate QR-Codes, and for each QR-Code
    - Show your smartphone to your webcam and hit 'j' to save the secets as .json
    - Enter a suitable filename to save the .json
  - Depending on the number of exported accounts, you may have to store more than one .json

You should now have one ore more .json files

```
> ls *.json
```

### Import of the TOTP secrets

Import the secrets to the target authenticator

```
> python ./totpsa.py *.json
```

### Use the target authenticator

#### Dave's authenticator

```
> authenticator list
> authenticator generate
```

## Security recommendations

### Only use authenticators that are designed securely

This adapter only supports authenticators with a command line interface (CLI) if it takes the following security concepts into account:

- the authenticator accepts secrets on the console (user input) and not (only) as program arguments or pipes,
  because we do not want to see the secret in plain text in process tables in multi-user environments. We also do not want to see secrets in plain text in command line history files.
- the authenticator encrypts its own database with a password and a secure state-of-the-art algorithm

### Protect the access to the secrets database of the authenticator

Use the protection mechanism of your authenticator and set a good password.
If you don't know how to set good passwords read [this article](https://www.bsi.bund.de/EN/Themen/Verbraucherinnen-und-Verbraucher/Informationen-und-Empfehlungen/Cyber-Sicherheitsempfehlungen/Accountschutz/Sichere-Passwoerter-erstellen/sichere-passwoerter-erstellen_node.html).

### Only transfer TOTP secrets by scanning QR codes

To transfer TOTP secrets you should prefer to use cameras only to read QR codes that contain the secrets.
Do not store the TOTP secrets on unencryted media such as paper or USB thumb drives, because it is impossible to remove data from them securely without destroying them.

### Remove the exported files after the import

You should remove the exported files after the import is done, because secrets should not be stored without encryption.

### Why using two or more different devices is better

The German Federal Office for Information Security (BSI) recommends always
using two different devices for the login and the second factor.
This significantly increases the protection of user accounts and data.

> The factors should always originate from more than one device. So you should not confirm payments with the device you use to initiate the transfer, for example. This makes it much more difficult for criminals to intercept your second factor.

Source: [BSI](https://www.bsi.bund.de/EN/Themen/Verbraucherinnen-und-Verbraucher/Informationen-und-Empfehlungen/Wie-geht-Internet/Zwei-Faktor-Authentisierung-Datensicherheit/zwei-faktor-authentisierung-datensicherheit_node.html)

and

> If you no longer have access to your possession-based factor or it breaks, you will usually lose access to the corresponding service or its functionality will be restricted. Take precautions for this scenario by — where possible — storing several 'second' factors.

Source: [BSI](https://www.bsi.bund.de/EN/Themen/Verbraucherinnen-und-Verbraucher/Informationen-und-Empfehlungen/Cyber-Sicherheitsempfehlungen/Accountschutz/Zwei-Faktor-Authentisierung/zwei-faktor-authentisierung_node.html)

### Encrypt your disks

If you use multiple devices with an authentication it is important that you protect each of those devices. Enabling disk encryption is best practice.

If your smartphone is not too old, the smartphone operating system has encryption enabled by default.
However, this might not be the case for notebooks, laptops, or desktop PCs.
If your notebook or laptop gets stolen, the thief could bypass the operating system protective measures and gain access to the disk hardware directly.
Disk encryption can prevent that threat. On Windows you could use Bitlocker or Veracrypt.


## The License

[MIT license](https://github.com/jonelo/totp-secrets-adapter/blob/main/LICENSE)

## References

- [Roland's extract_otp_secrets](https://github.com/scito/extract_otp_secrets)
- [Dave's authenticator](https://github.com/JeNeSuisPasDave/authenticator)
