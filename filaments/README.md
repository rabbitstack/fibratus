Fibratus incorporates a framework for painlessly extending the functionality and incorporating new features via Python scripts. 
These scripts are called **filaments**. You can also think of them as extension points with virtually endless possibilities. 
Whatever you are allowed to craft in Python, you can also implement in filaments.

- `fishy_netio` alerts when atypical processes produce network requests
- `registry_persistence` surfaces registry operations that would allow a process to execute on system startup
- `top_in_packets` shows the top TCP / UDP inbound packets by IP/port tuple
- `top_keys` shows the top registry keys by number of registry operations
- `top_out_packets` shows the top TCP / UDP outbound packets by IP/port tuple
- `watch_files` watches files and directories created in the file system
