import os
from typing import List, Dict
from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.engine.base import Engine
import argparse
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.engine.base import Engine
import pymssql
from urllib.parse import quote_plus
import traceback
import ipaddress
import sqlite3
import csv
import sys
import datetime
import requests

load_dotenv()  # Load environment variables from .env file
# load_dotenv('.env')  # Load environment variables from .env file


# print("Database connection details:")
# print(f"DB_USER: {os.getenv('DB_USER')}")
# print(f"DB_PASSWORD: {'*' * len(os.getenv('DB_PASSWORD')) if os.getenv('DB_PASSWORD') else 'Not set'}")
# print(f"DB_SERVER: {os.getenv('DB_SERVER')}")
# print(f"DB_NAME: {os.getenv('DB_NAME')}")



class DatabaseManager:
    def __init__(self):
        self.engine = self._create_engine()
        self.Session = sessionmaker(bind=self.engine)

    def _create_engine(self) -> Engine:
        try:
            db_user = os.getenv('DB_USER', '').strip()
            db_password = os.getenv('DB_PASSWORD', '').strip()
            db_server = os.getenv('DB_SERVER', '').strip()
            db_name = os.getenv('DB_NAME', '').strip()
            db_port = os.getenv('DB_PORT', '1433').strip()

            # In the _create_engine method, modify the connection string like this:
            db_password_encoded = quote_plus(db_password)
            connection_string = f"mssql+pymssql://{db_user}:{db_password_encoded}@{db_server}:{db_port}/{db_name}?charset=utf8"

            
            # print(f"Attempting to connect with: {connection_string.replace(db_password, '*****')}")
            
            # Try direct pymssql connection first
            try:
                conn = pymssql.connect(
                    server=db_server,
                    user=db_user,
                    password=db_password,
                    database=db_name,
                    timeout=30
                )
                # print_to_console("Direct pymssql connection successful!")
                conn.close()
            except pymssql.OperationalError as e:
                # print_to_console(f"Direct pymssql connection failed: {e}")
                raise
            
            engine = create_engine(
                connection_string,
                connect_args={'timeout': 30}  # Increase timeout to 30 seconds
            )
            
            # Test the SQLAlchemy connection
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            # print_to_console("SQLAlchemy connection successful!")
            return engine
        except (SQLAlchemyError, pymssql.Error) as e:
            print_to_console(f"Error creating engine: {e}")
            raise
        

    def execute_query(self, query, params=None):
        with self.engine.connect() as connection:
            result = connection.execute(text(query), params)
            columns = result.keys()
            return [dict(zip(columns, row)) for row in result.fetchall()]





class ApplicationManager:
    SIGNER_NAME = {}
    signed = {}

    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
        self.freq = {}

    def initialize(self):
        if 'comm_files.csv' in os.listdir('.\\'):    
            with open('comm_files.csv', 'r') as csv_file:
                csv_reader = csv.reader(csv_file)    
                
                for row in csv_reader:
                    self.freq[row[0]] = row[1]
                # print(f"Total Common Files: {len(comm_files)}")
        else:
            print("The 'comm_files.csv' not found, please re-run again with 'update' command")
            sys.exit(0) 
            
        #*******************************************************************************************        
        # Applications Signer Name
        #*******************************************************************************************
            
        file_path = 'SIGNER_NAME.csv'

        # Detect the encoding of the file
        # with open(file_path, 'rb') as rawdata:
            # result = chardet.detect(rawdata.read())
            # encoding = result['encoding']

        # Open the file with the detected encoding
        with open(file_path, 'r', encoding='latin-1') as csv_file:
            csv_reader = csv.reader(csv_file)
            header = next(csv_reader)
            
            for row in csv_reader:
                ApplicationManager.SIGNER_NAME[row[0]] = row[1]
                
        #*****************************************************************************
        # Sigcheck signed files
        # Note: We need to update the signed_apps.csv file by running sigcheck again
        #***************************************************************************** 
        signed_file_path = 'signed_apps.csv'
        with open(signed_file_path, 'r', newline='', encoding='utf-8') as input_file:
            reader = csv.reader(input_file)
            header = next(reader)  # Read and skip the header
            sha2_column_index = header.index("SHA256")
            signed_files = list(reader)
            
        for row in signed_files:
            ApplicationManager.signed[row[sha2_column_index]] = row


    def update_frequency(self):
        query = """
        SELECT [APP_HASH], [SHA2]
        FROM [sem5].[dbo].[SEM_APPLICATION]
        """
        records = self.db_manager.execute_query(query)
        
        for record in records:
            sha2 = record['SHA2']
            if self._is_valid_sha2(sha2):
                self.freq[sha2] = self.freq.get(sha2, 0) + 1

    @staticmethod
    def _is_valid_sha2(sha2: str) -> bool:
        return len(sha2) == 64 and all(c in "0123456789abcdefABCDEF" for c in sha2)

    def save_frequency(self, filename: str = 'comm_files.csv'):
        with open(filename, 'w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            for key, value in self.freq.items():
                writer.writerow([key, value])


def get_computer_info(db_manager, username):
    query = """
        SELECT 
            comp.[IP_ADDR1],
            comp.[COMPUTER_NAME],
            comp.[CURRENT_LOGIN_USER]
        FROM 
            [sem5].[dbo].[SEM_COMPUTER] comp 
        WHERE 
            comp.[CURRENT_LOGIN_USER] = :username
    """
    result = db_manager.execute_query(query, {'username': username})

    #columns = ['IP_ADDR1', 'COMPUTER_NAME', 'CURRENT_LOGIN_USER']
    # [dict(zip(columns, row)) for columns, row in result]
    return result
    

def get_user_applications(db_manager, username):
    
    where_clause = "comp.[CURRENT_LOGIN_USER] = :username"
    params = {'username': username}
    results = get_application_data(db_manager, where_clause, params)

    return results
    
    
    #*******************************************************************************************   
    # Search for Applications using current logged in user    
    #*******************************************************************************************
def handle_username_command(args, db_manager):
    try:
        computer_info = get_computer_info(db_manager, args.query)
        
        if computer_info:
            record = computer_info[0]

            ip_int = int(record['IP_ADDR1'].hex(), 16)  # Convert string to integer
            # integer_value = int(records[0]['IP_ADDR1'].hex(), 16)
            ip_address = ipaddress.ip_address(ip_int)
            print('COMPUTER_NAME\tIP Address\tCURRENT_LOGIN_USER')
            print(f"{record['COMPUTER_NAME']}\t{ip_address}\t{record['CURRENT_LOGIN_USER']}")
        else:
            print(f"No computer found for user: {args.query}")
            return
        
        # ... rest of your code ...

    except Exception as e:
        print_to_console(f"An error occurred: {e}")
        print_to_console(traceback.format_exc())



def is_common_or_signed_app(app):
    return (
        (app['SHA2'] in freq and int(freq[app['SHA2']]) > 4) or
        (app['SIGNER_NAME'] in SIGNER_NAME and int(SIGNER_NAME[app['SIGNER_NAME']]) > 4) or
        rdslookup(app['SHA2']) or
        app['SHA2'] in signed
    )



def validate_ip(query):
    try:
        ip_obj = ipaddress.ip_address(query)
        print(f"Searching for files on a machine using IP address: {query}")
        return True
    except ValueError:
        print(f"'{query}': is not a valid IP")
        return False


#*******************************************************************************************   
# Searching for files on a machine using its IP address
#******************************************************************************************* 
def search_files_computer_name(db_manager, query, freq, SIGNER_NAME, signed):

    where_clause = "comp.[COMPUTER_NAME] = :computer_name"
    params = {'computer_name': query}
    results = get_application_data(db_manager, where_clause, params)
    # print(results)

    # records = db_manager.execute_query(SQL_QUERY)
    # for r in results:
        # rows = rdslookup(r['SHA2'])
        # if not ((r['SHA2'] in freq and int(freq[r['SHA2']]) > 4) or 
                # (r['SIGNER_NAME'] in SIGNER_NAME and int(SIGNER_NAME[r['SIGNER_NAME']]) > 4) or 
                # rows or 
                # r['SHA2'] in signed):
            # print(f"{r['COMPUTER_NAME']},{r['CURRENT_LOGIN_USER']},{r['APPLICATION_NAME']},{r['APPLICATION_PATH']},{r['SHA2']}")
    return results


#*******************************************************************************************   
# Searching for files on a machine using its IP address
#******************************************************************************************* 

def search_files_ip_address(db_manager, query, freq, SIGNER_NAME, signed):
    ip_addr = '0x' + ''.join(f'{int(octet):02X}' for octet in query.split('.'))
    
    # First query to get the matching computers
    where_clause = "comp.[IP_ADDR1] = :ip_addr OR comp.[IP_ADDR2] = :ip_addr OR comp.[IP_ADDR3] = :ip_addr"
    params = {'ip_addr': ip_addr}
    
    sql_query = """
                SELECT 
                    comp.[IP_ADDR1],
                    comp.[IP_ADDR2],
                    comp.[IP_ADDR3],
                    comp.[COMPUTER_NAME],
                    comp.[CURRENT_LOGIN_USER]
                FROM 
                    [sem5].[dbo].[SEM_COMPUTER] comp 
                WHERE 
                    comp.[IP_ADDR1] = """ + ip_addr + """ OR
                    comp.[IP_ADDR2] = """ + ip_addr + """ OR
                    comp.[IP_ADDR3] = """ + ip_addr

    records = db_manager.execute_query(sql_query)
    

    if records:
        ip_addrs = []
        
        if records[0]['IP_ADDR1']:
            ip_addrs.append(f"{bin2dec_ip(records[0]['IP_ADDR1'])}")
        if records[0]['IP_ADDR2']:
            ip_addrs.append(f"{bin2dec_ip(records[0]['IP_ADDR2'])}")
        if records[0]['IP_ADDR3']:
            ip_addrs.append(f"{bin2dec_ip(records[0]['IP_ADDR3'])}")
        
        for idx, ip in enumerate(ip_addrs):
            if query in ip:
                record = records[0]
                
                print_to_console('COMPUTER_NAME,IP Address,CURRENT_LOGIN_USER')
                print_to_console(f"{record['COMPUTER_NAME']},{ip},{record['CURRENT_LOGIN_USER']}")
                
                ip_addr_column = f'IP_ADDR{idx + 1}'
                
                # Second query to get the applications for the matching IP
                where_clause = f"comp.{ip_addr_column} = :ip_addr"
                params = {'ip_addr': records[0][ip_addr_column]}

                app_records = get_application_data(db_manager, where_clause, params)

                # for r in app_records:
                    # rows = rdslookup(r['SHA2'])
                    # if not ((r['SHA2'] in freq and int(freq[r['SHA2']]) > 4) or 
                            # (r['SIGNER_NAME'] in SIGNER_NAME and int(SIGNER_NAME[r['SIGNER_NAME']]) > 4) or 
                            # rows or 
                            # r['SHA2'] in signed):
                        # print(f"{r['COMPUTER_NAME']},{r['CURRENT_LOGIN_USER']},{r['APPLICATION_NAME']},{r['APPLICATION_PATH']},{r['SHA2']}")
                        
                return app_records

#*******************************************************************************************   
# Search for files on machines using SHA256
#*******************************************************************************************
def search_files_sha256(db_manager, args):        
    if args.blklist:
        print_to_console('Read hashes from a file.')
        with open(args.blklist, 'r') as file:
            query = [line.strip().upper() for line in file.readlines()]
    else:
        query = [args.query.strip().upper()]  # Ensure single query is also in a list
    
    where_clause = "app.[SHA2] IN :sha_list"
    params = {'sha_list': tuple(query)}  # Now query is a list of complete SHA256 hashes

    results = get_application_data(db_manager, where_clause, params)
    for r in results:
        print(f"{r['COMPUTER_NAME']}\t{r['APPLICATION_NAME']}\t{r['APPLICATION_PATH']}\t{r['SHA2']}")        


def search_applications(db_manager, query, freq, SIGNER_NAME, signed):
    where_clause = "app.[APPLICATION_NAME] LIKE :app_name"
    params = {'app_name': f'%{query}%'}
    
    records = get_application_data(db_manager, where_clause, params)
    
    return records
            
def get_application_data(db_manager, where_clause, params=None):
    query = """
    SELECT 
        app.[APPLICATION_NAME],
        app.[APPLICATION_PATH],
        app.[SHA2],
        app.[SIGNER_NAME],
        app.[TIME_STAMP],
        comp.[COMPUTER_NAME],
        comp.[CURRENT_LOGIN_USER],
        comp.[IP_ADDR1],
        comp.[IP_ADDR2],
        comp.[IP_ADDR3]
    FROM 
        [sem5].[dbo].[SEM_APPLICATION] app
    INNER JOIN [sem5].[dbo].[COMPUTER_APPLICATION] comp_app 
        ON app.[APP_HASH] = comp_app.[APP_HASH]
    INNER JOIN [sem5].[dbo].[SEM_COMPUTER] comp 
        ON comp_app.[COMPUTER_ID] = comp.[COMPUTER_ID]
    WHERE 
        {where_clause}
    """
    
    formatted_query = query.format(where_clause=where_clause)

    return db_manager.execute_query(formatted_query, params)
    
VT_KEY = os.getenv('VT_KEY', '').strip()    
def VirustotalSearch(sha256_hash):
    # Replace 'YOUR_API_KEY' with your actual VirusTotal API key

    # Replace 'your_sha256_hash' with the SHA-256 hash of the file you want to check
    #sha256_hash = '06917fc270a0324e8d28da83bedf6d1638bb430876b8336dd326517d33251bb1'

    # URL for querying the VirusTotal API
    url = f'https://www.virustotal.com/api/v3/files/{sha256_hash}'

    # Set up headers with the API key
    headers = {
        'x-apikey': VT_KEY,
    }
    
    # response = requests.get(url, headers=headers)
    # print_to_console(response)
    # print_to_console(sha256_hash)
    # sys.exit(0)

    try:
        # Send a GET request to the VirusTotal API
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            # Parse the JSON response
            data = response.json()
            # print(data)
            # Check if the file is in VirusTotal's database
            if 'data' in data:
                attributes = data['data']['attributes']
                last_analysis_stats = attributes['last_analysis_stats']

                # Count the number of engines that detected the file as malicious
                malicious_count = last_analysis_stats['malicious']
                last_analysis_results = attributes['last_analysis_results']


                # Calculate the detection rate
                detection_rate = (malicious_count / len(last_analysis_results)) * 100

                #print(f"File with SHA-256 hash {sha256_hash} has a detection rate of {detection_rate:.2f}% ({malicious_count}/{len(last_analysis_results)} engines detected it as malicious).")
                return f"{malicious_count}/{len(last_analysis_results)}"
            else:
                print_to_console(f"File with SHA-256 hash {sha256_hash} is not found on VirusTotal.")
        elif response.status_code == 404:
            return "Not Found"
            #print(f"Error: {response.status_code} - {response.text}")
    except Exception as e:
        print_to_console(f"An error occurred: {e}")
#*****************************************************************************
# SQLlite Databse
#*****************************************************************************
# Replace 'your_table_name' with the actual table name you want to query

def rdslookup(sha2):
    database_path = 'RDS_2024.03.1\\RDS_2024.03.1.db'
    table_name = 'FILE'
    
    query = f'SELECT sha256 FROM {table_name} WHERE sha256 = ?'
    
    try:
        with sqlite3.connect(database_path, timeout=30) as conn:
            conn.execute('PRAGMA journal_mode = WAL')
            conn.execute('PRAGMA cache_size = -1048576')  # 1GB cache
            
            cursor = conn.cursor()
            cursor.execute(query, (sha2,))
            result = cursor.fetchone()
            
            return result[0] if result else None
    
    except sqlite3.Error as e:
        print_to_console(f"An error occurred: {e}")
        return None

    
def bin2dec_ip(bin_IP):
    integer_value = int(bin_IP.hex(), 16)
    ip_address = ipaddress.ip_address(integer_value)

    return ip_address    

def print_to_console(message):
    is_redirected = not sys.stdout.isatty()
    
    if is_redirected:
        print(message, file=sys.stderr, flush=True)
        return
    print(message)
    
def print_results(records, freq, SIGNER_NAME, signed):

    print("TIME_STAMP, COMPUTER_NAME, CURRENT_LOGIN_USER, APPLICATION_PATH, APPLICATION_NAME, SHA2, VirusTotal")

    for r in records:
        in_rds = rdslookup(r['SHA2'])
        # if in_rds:
            # print_to_console(in_rds)
            
        if not ((r['SHA2'] in freq and int(freq[r['SHA2']]) > 4) or 
                (r['SIGNER_NAME'] in SIGNER_NAME and int(SIGNER_NAME[r['SIGNER_NAME']]) > 4) or 
                in_rds or 
                r['SHA2'] in signed):
                
            # Convert milliseconds timestamp to seconds
            timestamp_seconds = r['TIME_STAMP'] / 1000.0
            
            # Convert to datetime object
            date_time = datetime.datetime.fromtimestamp(timestamp_seconds)
            date_time = date_time.replace(microsecond=0)
            vt_detection = VirustotalSearch(r['SHA2'])

            print(f"{date_time}, {r['COMPUTER_NAME']}, {r['CURRENT_LOGIN_USER']}, {r['APPLICATION_PATH']}, {r['APPLICATION_NAME']}, {r['SHA2']}, {vt_detection}".encode('latin-1', errors='ignore').decode('latin-1'))

def main():
    
    available_commands = ['computer_name', 'username', 'addr', 'sha2', 'app', 'update']

    parser = argparse.ArgumentParser(description='Lookup tool for SEPM MSSQL.')
    parser.add_argument('command', type=str,  choices=available_commands, help='The command to execute')
    #parser.add_argument('-q', help='What are you looking for?', metavar='query', default=False)
    parser.add_argument('-q', '--query', help='What are you looking for?', nargs='?', default=None)
    parser.add_argument('-bl', '--blklist', help='Black list file of sha2', metavar='<File>', default=False)
    #argParser.add_argument('-r', help='Output format, supported only csv', metavar='csv', default=False)
    
    args = parser.parse_args()
    
    db_manager = DatabaseManager()
    app_manager = ApplicationManager(db_manager)
    # In your main logic:
    
    
    if args.command == 'update':
        print_to_console("Updating the comm_files.csv ...")
        app_manager.update_frequency()
        return
        
    
    elif not args.query and not args.blklist:
        parser.print_help()
        print_to_console('Must provide either option -q or -bl')
        return
        
    else:
        app_manager.initialize()
        
        
    records = None    
    if args.command == 'username':
        # handle_username_command(args, db_manager)
        records = get_user_applications(db_manager, args.query)        

        
    elif args.command == 'addr':
        if not validate_ip(args.query):
            return
        records = search_files_ip_address(db_manager, args.query, app_manager.freq, ApplicationManager.SIGNER_NAME, ApplicationManager.signed)
        
    elif args.command == 'computer_name':
        records = search_files_computer_name(db_manager, args.query, app_manager.freq, ApplicationManager.SIGNER_NAME, ApplicationManager.signed)
        
        
    elif args.command == 'sha2' or args.command == 'SHA2':
        search_files_sha256(db_manager, args)
        
        
    elif args.command == 'app':
        records = search_applications(db_manager, args.query, app_manager.freq, ApplicationManager.SIGNER_NAME, ApplicationManager.signed)
           
    else:
        print('Command not found!')
        sys.exit(0) 

    if records:
        print_results(records, app_manager.freq, ApplicationManager.SIGNER_NAME, ApplicationManager.signed)

 

if __name__ == "__main__":
    main()
