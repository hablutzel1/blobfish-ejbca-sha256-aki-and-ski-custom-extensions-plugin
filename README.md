# EJBCA - SHA-256 AKI and SKI Custom Extensions Plugin

## Installation

First, proceed with the plugin installation taking as reference https://github.com/hablutzel1/blobfish-ejbca-dynamic-criticality-custom-extension-plugin/blob/master/README.md#installation-and-usage.

## Usage

Now, both, the **SHA-256 AKI Certificate Extension** and the **SHA-256 SKI Certificate Extension** custom extensions need to be configured from the Admin GUI, section “System Configuration > Custom Certificate Extensions” as follows:

* SHA-256 AKI Certificate Extension
  * Object Identifier (OID): 2.5.29.35
  * Label: Sha256Aki
  * Extension Class: SHA-256 AKI Certificate Extension
  * Critical: Disabled
  * Required: Active
  * Dynamic: true
  * Encoding: RAW
  
* SHA-256 SKI Certificate Extension
  * Object Identifier (OID): 2.5.29.14
  * Label: Sha256Ski
  * Extension Class: SHA-256 SKI Certificate Extension
  * Critical: Disabled
  * Required: Active
  * Dynamic: true
  * Encoding: RAW

Then these custom extensions need to be configured in the corresponding root CA, sub CA or EE Certificate Profiles like this:

* Authority Key ID: Disabled
* Subject Key ID: Disabled
* Used Custom Certificate Extensions:
  * Sha256Aki
  * Sha256Ski

Note that these extensions require to be active at the same time in the certificate profile to ensure consistency across the AKI and SKI identifiers, otherwise, for example, when generating a root CA, AKI might be based on SHA-256 while SKI might still be based on SHA-1. 



