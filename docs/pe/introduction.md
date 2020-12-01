# Portable Executable Introspection

[Portable Executable](https://en.wikipedia.org/wiki/Portable_Executable) (PE) is the Windows file format that describes the layout of the executable code. PE is frequently subject to weaponization ranging from reverse shell payload injections to several obfuscation techniques used by malware creators.

Fibratus natively supports the scanning of the PE format data that, for example, underpins the [PE filters](/filters/fields?id=pe). To enable the PE introspection, it is necessary to edit the `pe.enabled` key in the configuration file or provide the `--pe.enabled=true` command line flag.

### Excluding executables {docsify-ignore}

When the PE introspection is enabled, Fibratus will try to obtain the PE data for every running process in the system. This happens during Fibratus bootstrap stage, but also when a new process is spawn. To skip gathering the PE data for some process images, you can add the image name under the `excluded-images` key in the configuration file. Avoiding the parsing of the PE format data for some process images, alleviates the pressure on Fibratus and reduces resource usage.
