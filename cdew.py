# Capture Digital Evidences of a Website (CDEW)
from urllib.request import urlopen, HTTPError
import urllib.request
import hashlib
import rfc3161ng
from bs4 import BeautifulSoup
import os.path
import time
import datetime
import re
import csv
from pyasn1.codec.der import decoder
import requests
import urllib
import argparse

CODE_PATH = 'codes'
CERTIFICATE_PATH = 'certificates'
CERTIFICATE = 'data_certum_certificate.crt'
REGISTER_PATH = 'registers'
RESPONSE_PATH = 'responses'


# Mapping of website
def website_mapping(url, header):
    # Create register
    filename = datetime.datetime.now().strftime("%Y%m%d_%H_%M_%S") + '.csv'
    current_directory = os.path.dirname(os.path.realpath(__file__))
    filename_path = os.path.join(current_directory, REGISTER_PATH, filename)
    with open(filename_path, 'w', newline='') as f:
        fieldnames = ['ID', 'Label', 'Time-Stamp', 'Hash', 'TSA', 'Commentary']
        csv_file = csv.DictWriter(f, fieldnames=fieldnames)
        csv_file.writeheader()

        # Connect to a URL
        req = urllib.request.Request(url, headers=header)
        response = urlopen(req)

        # Read html code
        html = response.read()

        soup = BeautifulSoup(html, "html.parser")

        # Get links
        links = soup.findAll('a')

        lista = {}

        id_count = 1
        for link in links:
            label = ''
            timestamp = ''
            hash_hex = ''
            tsa_response = ''
            commentary = ''
            try:
                label = re.sub('[^A-Za-z0-9/s]+', '', link.text)
                # label = link.text

                sub_url = url + '/' + link.attrs['href']

                # Get web code
                time.sleep(2)
                data = get_web_code(sub_url, header)
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H_%M_%S")

                lista[label] = str(data)

                # Write html
                try:
                    write_file(CODE_PATH, label + '.html', data)
                except IOError as io:
                    commentary += 'Digital Evidence ' + label + 'cannot be captured. '
                    raise Exception

                # Calculate the hash of the digital evidence
                try:
                    hash_object = calculate_sha256(data)
                    hash_hex = hash_object.hexdigest()
                    print('Hash ' + label + ':', hash_hex)
                    hash_encoded = hash_hex.encode()
                except IOError as io:
                    commentary += 'The hash of ' + label + 'cannot be calculated. '
                    raise Exception

                # Add TSA
                try:
                    tsa_response = add_tsa(label, hash_encoded)
                except IOError as io:
                    commentary += 'The TSA of ' + label + 'cannot be added. '
                    raise Exception

                # Record register
                csv_file.writerow({'ID': str(id_count), 'Label': label, 'Time-Stamp': timestamp,
                                   'Hash': hash_hex, 'TSA': tsa_response,
                                   'Commentary': commentary})
                id_count += 1

            except Exception as e:
                commentary = commentary + str(e)
                csv_file.writerow({'ID': str(id_count), 'Label': label, 'Time-Stamp': timestamp,
                                   'Hash': hash_hex, 'TSA': tsa_response,
                                   'Commentary': commentary})

    return html, links


# Get code of website
def get_web_code(url, header):
    req = urllib.request.Request(url, headers=header)
    try:
        response = urlopen(req)
        code = response.read()
        return code
    except HTTPError as e:
        print(datetime.datetime.now())
        if e.code == 429:
            time.sleep(11)
            return get_web_code(url, header)


# Calculate hash SHA256
def calculate_sha256(data):
    return hashlib.sha256(data)


def add_tsa(text, hash_data):
    url = 'http://time.certum.pl'
    certificate = open(CERTIFICATE, 'rb').read()
    rt = rfc3161ng.RemoteTimestamper(url, certificate=certificate, include_tsa_certificate=True)
    write_file(CERTIFICATE_PATH, 'certificate ' + text + '.crt', rt.certificate)
    tst = rt.timestamp(data=hash_data)

    tsq = rfc3161ng.make_timestamp_request(data=hash_data)
    binary_request = rfc3161ng.encode_timestamp_request(tsq)
    headers = {'Content-Type': 'application/timestamp-query'}
    response = requests.post(
        url,
        data=binary_request,
        timeout=10,
        headers=headers,
    )
    tsr = rfc3161ng.decode_timestamp_response(response.content)

    tst1, substrate = decoder.decode(tst, asn1Spec=rfc3161ng.TimeStampToken())

    signed_data = tst1.content
    signer_info = signed_data['signerInfos'][0]
    tsa_signature = bytes(signer_info['encryptedDigest']).hex()

    write_object_file(RESPONSE_PATH, 'response ' + text + '.tsr', tsr)

    # with open("Output.txt", "w") as text_file:
    #     text_file.write("%s" % tsr)

    tst = tsr.time_stamp_token
    tst1 = tst.content
    tst2 = tst.tst_info
    tss = tsr.status

    return tsa_signature


# Write file
def write_file(folder, filename, data):
    current_directory = os.path.dirname(os.path.realpath(__file__))
    filename_path = os.path.join(current_directory, folder, filename)
    f = open(filename_path, 'wb')
    f.write(data)
    f.close()


# Write one object in a file
def write_object_file(folder, filename, data):
    current_directory = os.path.dirname(os.path.realpath(__file__))
    filename_path = os.path.join(current_directory, folder, filename)
    f = open(filename_path, 'w')
    f.write("%s" % data)
    f.close()


# Register
# Create CSV
def create_csv(filename):
    filename = filename + '.csv'
    current_directory = os.path.dirname(os.path.realpath(__file__))
    filename_path = os.path.join(current_directory, REGISTER_PATH, filename)
    with open(filename_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['ID', 'Label', 'Time-Stamp', 'Hash', 'TSA'])
        return writer


# Add data in CSV
def add_data_csv(writer, data):
    try:
        writer.writerows(data)
    except Exception as e:
        print(e)


# Close CSV
def close_csv(writer):
    writer.close()


# Parse command line arguments
def parse_arguments(self):
    parser = argparse.ArgumentParser(prog="cdew.py", formatter_class=argparse.RawTextHelpFormatter,
                                     description="Capture Digital Evidences of a Website")

    parser.add_argument("url", type=str, nargs=1, help="URL of the website")

    # run the parsing
    args = parser.parse_args(self)

    # Input Path
    url = args.url[0]

    return url


# Check folders
def check_folders():
    current_directory = os.path.dirname(os.path.realpath(__file__))
    if not os.path.exists(os.path.join(current_directory, CODE_PATH)):
        os.makedirs(os.path.join(current_directory, CODE_PATH))
    if not os.path.exists(os.path.join(current_directory, CERTIFICATE_PATH)):
        os.makedirs(os.path.join(current_directory,CERTIFICATE_PATH))
    if not os.path.exists(os.path.join(current_directory, REGISTER_PATH)):
        os.makedirs(os.path.join(current_directory, REGISTER_PATH))
    if not os.path.exists(os.path.join(current_directory, RESPONSE_PATH)):
        os.makedirs(os.path.join(current_directory, RESPONSE_PATH))


if __name__ == "__main__":
    import sys

    print('Init')
    # Check folders
    check_folders()

    # Parse arguments
    website_url = parse_arguments(sys.argv[1:])

    # Capture digital evidences of a website
    url_header = {"Accept-Language": "es-Es,es;q=0.9"}
    [html_code, links_list] = website_mapping(website_url, url_header)
    print('Finish')