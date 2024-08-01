# SEPMmsql-Lookup
Query Symantec SEPM Console MSQL databse

python SEPMsql-Lookup.py -h
usage: SEPMsql-Lookup.py [-h] [-q [QUERY]] [-bl <File>] {computer_name,username,addr,sha2,app,update}

Lookup tool for SEPM MSSQL.

positional arguments:
  {computer_name,username,addr,sha2,app,update}
                        The command to execute

options:
  -h, --help            show this help message and exit
  -q [QUERY], --query [QUERY]
                        What are you looking for?
  -bl <File>, --blklist <File>
                        Black list file of sha2
