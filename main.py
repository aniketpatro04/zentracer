import requests
import time
import socket

# TO DO:

# Resolve the Port Name Getting 0 for both addresses, 

# Note: By Default the Port Number is 0. We need to do a TCP oing to check if it is open

# Note: Port 0 is Null (No Port Specified / No Service Specified). Use a separate TCP Ping (Curl) to check if IP is valid and port is available / open

# V2: Upgrade so that IP Address of Usuable Ports and Services are returned (Check Documentation)

def get_domain_user_input():

    domain_name = input("Enter the Domain name to Trace: ")

    domain_name_sample = domain_name.replace("https://", "").replace("http://", "").split("/")[0]

    return domain_name_sample,domain_name

def get_ip_info(domain_name_sample):

    """
    Resolves a domain and returns the first available IPv4 and IPv6 addresses.
    Returns Basic IP Info. To Check you have to run separate TCP / Port Pings for particualr services
    """
    addresses = {"IPv4": None, "IPv6": None, "Port_v4":None , "Port_v6":None}

    try:

        results = socket.getaddrinfo(domain_name_sample,None)

        for result in results:
            family, _, _, _, sockaddr = result
            ip_addr = sockaddr[0]
            port_num = sockaddr[1]

            if family == socket.AF_INET and addresses["IPv4"] is None:
                addresses["IPv4"] = ip_addr
                addresses["Port_v4"] = port_num


            if family == socket.AF_INET6 and addresses["IPv6"] is None:
                addresses["IPv6"] = ip_addr
                addresses["Port_v6"] = port_num

            if addresses["IPv4"] and addresses["IPv6"]:
                break

    except socket.gaierror as e:
        # Error 8 is usually 'nodename nor servname provided, or not known'
        return f"DNS Resolution Error: {e.strerror} (Domain: {domain_name_sample})"
    except Exception as e:
        return f"Unexpected Error: {str(e)}"
    

    return addresses


def get_response_time(url):

    start_time = time.time()
    response = requests.get(url)
    end_time = time.time()

    response_time = end_time - start_time

    return response_time

def print_header_info(url):

    response = requests.get(url)

    for key,value in response.headers.items():

        print(f"{key} : {value}")


if __name__ == "__main__":
    
    sample,url = get_domain_user_input()
    res = get_ip_info(sample)

    print("########## IP Address Info ##########")
    print(res)
    print("\n")
    print("\n")
    print("########## Response Time ##########")
    print(get_response_time(url), "seconds")
    print("\n")
    print("\n")
    print("########## Header Info ##########")
    print_header_info(url)
