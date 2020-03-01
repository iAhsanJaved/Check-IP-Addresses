import os
import socket
import requests
import sqlite3
from sqlite3 import Error
from urllib.parse import urlparse
from requests.exceptions import HTTPError
from datetime import datetime

import pandas as pd

# https://iphub.info/api
API_KEY = ''

def get_api_result(ip):
    result = None
    try:
        url = 'http://v2.api.iphub.info/ip/'+ip

        response = requests.get(url, headers={'X-Key': API_KEY})
        # If the response was successful, no Exception will be raised
        response.raise_for_status()
    except HTTPError as http_err:
        print(f'\tHTTP error occurred: {http_err}')  # Python 3.6
    except Exception as err:
        print(f'\tOther error occurred: {err}')  # Python 3.6
    else:
        result = response.json()
    return response.status_code, result


# Source: https://stackoverflow.com/questions/3462784/check-if-a-string-matches-an-ip-address-pattern-in-python/48231784
def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False

    return True

def is_valid_ipv6_address(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        return False
    return True

# Source: https://stackoverflow.com/questions/7160737/python-how-to-validate-a-url-in-python-malformed-or-not
def is_url(url):
  try:
    result = urlparse(url)
    return all([result.scheme, result.netloc])
  except ValueError:
    return False

def create_connection(db_file):
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        return conn
    except Error as e:
        print(e)
 
    return conn

def get_unchecked_ip(conn):
    sql = "SELECT * FROM ip_addresses WHERE checked IS NULL OR checked = ''"
    df = pd.read_sql_query(sql, conn)
    return df

def change_checked_status(conn, ip_id, status):
    sql = "UPDATE ip_addresses SET checked='{0}' WHERE id={1}".format(status, ip_id)
    cur = conn.cursor()
    cur.execute(sql)
    conn.commit()

def add_ip_result(conn, result_row):
    sql = ''' INSERT INTO results(ip_id,checkDateTime,ip,countryCode,countryName,asn,isp,block,hostname)
              VALUES(?,?,?,?,?,?,?,?,?) '''
    cur = conn.cursor()
    cur.execute(sql, result_row)
    conn.commit()
    return cur.lastrowid



if __name__ == '__main__':
    dbFile = input('Enter the name of database file (ip_data.db): ')
    # Check database file exists
    if not os.path.isfile(dbFile):
        print('Error: "{}" database file does not exists.'.format(dbFile))
        exit()

    # Step-1: Create connection
    print('Step-1: Creating database connection...')
    conn = create_connection(dbFile)
    
    # Step-2: Get all the uncheck IP addresses
    print('Step-2: Get all the uncheck IP addresses...')
    df_ip_addresses = get_unchecked_ip(conn)
    
    # Check ip_addresses table is empty or not
    if df_ip_addresses.empty:
        print('\tError: There is no record in ip_addresses table')
        exit()
    else:
        # Step-3: Check each IP address
        print('Step-3: Check each IP address...')
        for index, row in df_ip_addresses.iterrows():
            ip_id = row["id"]
            ip = row["ip"]
            checked_status = ''

            # Check IP is valid or not
            if is_valid_ipv4_address(ip):
                checked_status = 'Valid'
            elif is_valid_ipv6_address(ip):
                checked_status = 'Valid'
            elif is_url(ip):
                checked_status = 'Valid'
            else:
                checked_status = 'Invalid' 

            print(f'\tIP: {ip}')
            if checked_status != 'Invalid':
                res_code, result = get_api_result(ip)
                if res_code == 200:
                    checked_status = 'Success'
                    checkDateTime = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
                    result_ip = str(result.get('ip', ''))
                    result_countryCode = str(result.get('countryCode', ''))
                    result_countryName = str(result.get('countryName', ''))
                    result_asn = str(result.get('asn', ''))
                    result_isp = str(result.get('isp', ''))
                    result_block = str(result.get('block', ''))
                    result_hostname = str(result.get('hostname', ''))

                    result_row = (ip_id, checkDateTime, result_ip, result_countryCode, result_countryName, result_asn, result_isp, result_block, result_hostname)
                    print(f'\t{result_row}')
                    add_ip_result(conn, result_row)
                
                elif res_code == 403:
                    print('\tError: Invalid API key.')
                    exit()
                elif res_code == 429:
                    print('\tError: API limit exceeded.')
                    exit()
                elif res_code == 422:
                    checked_status = 'Invalid'
                else:
                    checked_status = 'Failed'

                

            change_checked_status(conn, ip_id, checked_status)
            print(f'\tChecked Status: {checked_status}')


