import shodan
import sys
import os
import time

# Put your real API key here
api = shodan.Shodan("PEQau1ajHyzmDymnZcC49z3TgxMclIALj")


def complete_search(p1: str) -> None:
    """Comprehensive search: writes all results to results.txt"""
    try:
        results = api.search(p1)
        with open('results.txt', 'w', encoding='utf-8') as f:
            f.write("Results found: %s\n" % results['total'])
            print("Results found: %s" % results['total'])

            for result in results['matches']:
                try:
                    f.write('IP: %s\n' % result.get('ip_str', 'n/a'))
                    f.write(result.get('data', '') + "\n")
                    f.write("\n")
                except Exception as e:
                    print(f"Error writing result: {e}")
                    continue

        print("DONE, see the results.txt file")
    except shodan.APIError as e:
        print("Error: %s" % e)


def basic_search(p2: str) -> None:
    """Basic search: prints and saves only IPs"""
    try:
        result = api.search(p2)
        with open('results.txt', 'w', encoding='utf-8') as f:
            print("Results found: %s" % result['total'])
            f.write("Results found: %s\n" % result['total'])

            for service in result['matches']:
                try:
                    ip_str = service.get('ip_str', 'n/a')
                    print(ip_str)
                    f.write(ip_str + "\n")
                except Exception:
                    continue

        print("DONE, see the results.txt file")
    except Exception as e:
        print("Error: %s" % e)
        sys.exit(1)


def specific_search(p3: str) -> None:
    """Search a specific known IP"""
    try:
        host = api.host(p3)
    except shodan.APIError as e:
        print("Error: %s" % e)
        return

    with open('results.txt', 'w', encoding='utf-8') as f:
        try:
            f.write(
                "IP: {ip}\nOrganization: {org}\nOperating System: {os}\n\n".format(
                    ip=host.get('ip_str', 'n/a'),
                    org=host.get('org', 'n/a'),
                    os=host.get('os', 'n/a'),
                )
            )

            # Write all banners
            for item in host.get('data', []):
                f.write("Port: {port}\nBanner: {banner}\n\n".format(
                    port=item.get('port', 'n/a'),
                    banner=item.get('data', '').strip()
                ))
        except Exception as e:
            print(f"Error writing host data: {e}")

    print("DONE, see the results.txt file")


def specific_subnet_search(subnet_prefix: str) -> None:
    """
    Search all hosts in a /24 subnet.
    subnet_prefix example: '192.168.1.'  (note trailing dot!)
    """
    for x in range(255):
        ip = f"{subnet_prefix}{x}"
        try:
            host = api.host(ip)
            service_file = f"service.{ip}.txt"

            with open('results.csv', 'a', encoding='utf-8') as f, \
                 open(service_file, 'w', encoding='utf-8') as f2:

                try:
                    # Basic host info
                    f.write('{},{},{}'.format(
                        host.get('ip_str', 'n/a'),
                        host.get('org', 'n/a'),
                        host.get('os', 'n/a')
                    ))

                    ports = ""
                    services = ""
                    for item in host.get('data', []):
                        port = item.get('port', '')
                        banner = item.get('data', '').replace('\n', ' ').strip()
                        ports += f"{port}|"
                        services += f"{port}:{banner}|"

                    f.write(",%s\n" % ports)
                    f2.write(services)

                    print(f"[+] {ip}")
                except Exception as e:
                    print(f"Error processing {ip}: {e}")

        except Exception as e:
            print(f"[-] {ip} - {e}")

        # Be nice to the API
        time.sleep(1)


def main() -> None:
    banner = r"""\
          /$$$$$$  /$$                       /$$
         /$$__  $$| $$                      | $$
        | $$  \__/| $$$$$$$   /$$$$$$   /$$$$$$$  /$$$$$$  /$$$$$$$
        |  $$$$$$ | $$__  $$ /$$__  $$ /$$__  $$ |____  $$| $$__  $$
         \____  $$| $$  \ $$| $$  \ $$| $$  | $$  /$$$$$$$| $$  \ $$
         /$$  \ $$| $$  | $$| $$  | $$| $$  | $$ /$$__  $$| $$  | $$
        |  $$$$$$/| $$  | $$|  $$$$$$/|  $$$$$$$|  $$$$$$$| $$  | $$
         \______/ |__/  |__/ \______/  \_______/ \_______/|__/  |__/
          /$$$$$$                                          /$$
         /$$__  $$                                        | $$
        | $$  \__/  /$$$$$$   /$$$$$$   /$$$$$$   /$$$$$$$| $$$$$$$   /$$$$$$   /$$$$$$
        |  $$$$$$  /$$__  $$ |____  $$ /$$__  $$ /$$_____/| $$__  $$ /$$__  $$ /$$__  $$
         \____  $$| $$$$$$$$  /$$$$$$$| $$  \__/| $$      | $$  \ $$| $$$$$$$$| $$  \__/
         /$$  \ $$| $$_____/ /$$__  $$| $$      | $$      | $$  | $$| $$_____/| $$
        |  $$$$$$/|  $$$$$$$|  $$$$$$$| $$      |  $$$$$$$| $$  | $$|  $$$$$$$| $$
         \______/  \_______/ \_______/|__/       \_______/|__/  |__/ \_______/|__/

          By Dviros
    """
    print(banner)
    print("Select search type:")
    print("1 = Comprehensive search (returned as JSON, can be used for IPs and keywords)")
    print("2 = Basic search (Used for keywords, can be used also with IPs)")
    print("3 = Specific known IP search")
    print("4 = Search Subnet (format: XXX.XXX.XXX. example 192.168.1.)")
    print("5 = Search in list of Subnets")

    try:
        selection = int(input("Selection (1-5): ").strip())
    except ValueError:
        print("Invalid selection.")
        time.sleep(1)
        return main()

    if selection == 1:
        query = input("What's the IP or query? ").strip()
        complete_search(query)
    elif selection == 2:
        query = input("What's the IP or keyword? ").strip()
        basic_search(query)
    elif selection == 3:
        ip = input("What's the IP? ").strip()
        specific_search(ip)
    elif selection == 4:
        subnet = input("Specify the subnet (e.g. 192.168.1.): ").strip()
        # TODO: verify user input
        specific_subnet_search(subnet)
    elif selection == 5:
        filepath = input("Specify file name and path containing subnets list: ").strip()
        if not os.path.isfile(filepath):
            print(f"File path {filepath} does not exist. Exiting...")
            sys.exit(1)

        with open(filepath, encoding='utf-8') as fp:
            for line in fp:
                subnet = line.strip()
                if subnet:
                    specific_subnet_search(subnet)
    else:
        print("Invalid selection.")
        time.sleep(1)
        return main()


if __name__ == "__main__":
    main()
