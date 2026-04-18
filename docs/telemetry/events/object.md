# Object Manager Events

##### **Fibratus** captures the `CreateSymbolicLinkObject` event when a symbolic link object is created via native APIs. The Windows kernel emits an event that includes key metadata such as the link name, target path, and the process responsible for the operation.

### `CreateSymbolicLinkObject`

This visibility is particularly valuable because symbolic links are often leveraged by both legitimate system components and adversaries to redirect access to sensitive resources or obscure execution paths. By capturing these events in real time and correlating them with other system activity, Fibratus allows analysts to detect anomalous link creation patterns, trace their origin, and incorporate them into behavioral detections.

`CreateSymbolicLinkObject` has the following parameters:

| PARAMETER  | DESCRIPTION |
| :---        |    :----   |
| `source` | Source symbolic link object or other kernel object, for example, `DosDevices\PROCEXP152` |
| `target` | Target symbolic link object or other kernel object, for example, `\Device\PROCEXP152` |
| `desired_access` | Access rights for the target symbolic link object. Can be the combination of `DELETE`, `READ_CONTROL`, `WRITE_DAC`, `WRITE_OWNER`, `SYNCHRONIZE`, `STANDARD_RIGHTS_REQUIRED`, `STANDARD_RIGHTS_ALL`, `ACCESS_SYSTEM_SECURITY`, `MAXIMUM_ALLOWED`, `GENERIC_READ`, `GENERIC_WRITE`, `GENERIC_EXECUTE`, `GENERIC_ALL` |
| `status` | System status code that represents the outcome of the operation. |
