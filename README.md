# Backup Decryption Tool

This tool allows you to decrypt encrypted, locally stored iPhone backups created using iOS13 or newer versions. It does not support backups stored on iCloud.


## Install

Ensure you have [Python 3.4](https://www.python.org/) or a more recent version.

```bash
pip install -r requirements.txt
```
 


## Installation

Ensure you have [Python 3.4](https://www.python.org/) or a newer version installed on your system.

```bash
pip install -r requirements.txt
```
## How to Use

Refer to src/test.py for usage examples.

To decrypt files, you must know the relativePath of the targeted file(s). For frequently accessed files, such as those for call history or text message databases, you can use predefined constants from the RelativePath class. For example, use RelativePath.CALL_HISTORY instead of the full Library/CallHistoryDB/CallHistory.storedata.