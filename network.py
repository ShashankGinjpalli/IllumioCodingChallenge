import csv

class Firewall:

    csvDat = []

    def __init__(self,csv_Location):
        with open(csv_Location) as csv_file:
            csvParser = csv.reader(csv_file,delimiter = ',')
            for row in csvParser:
                port = row[2]
                ip = row[3]

                if('-' in port and '-' in ip):
                    port = port.split('-')
                    ip = ip.split('-')
                    ip[0] = ip[0].split('.')
                    ip[1] = ip[1].split('.')

                elif ('-' in port and '-' not in ip):
                    port = port.split('-')
                    ip = [ip.split('.')]

                elif ('-' not in port and '-' in ip):
                    port = [int(port)]
                    ip = ip.split('-')
                    ip[0] = ip[0].split('.')
                    ip[1] = ip[1].split('.')

                else:
                    port = [int(port)]
                    ip = [ip.split(".")]

                # saving the port and the ip as a list so that i wont have to write repetetive code in order to check for
                # a range
                self.csvDat.append((row[0],row[1],port,ip))




    def ip_check(self, ip, test_ip_address):
        # the code inside of the if is run if the code is
        if(len(ip) == 2):
            for i in range(4):
                # print(ip[0][i], ip_address[i], )
                if(int(ip[0][i]) <= int(test_ip_address[i])  <= int(ip[1][i])):
                    continue
                else:
                    return False
        else:
            for i in range(4):
                if (ip[0][i] == test_ip_address[i]):
                    continue
                else:
                    return False
        # only returns true if the algorithm makes it all the way through the ip address and all of the numbers either
        # match or exist in a range
        return True

    def accept_packet(self,direction,protocol,port,ip_address):
        ip_address = ip_address.split('.')
        print(direction,protocol,port,ip_address)

        for i in self.csvDat:

            # unpacking the values this way so that a very large input wont cause the program to crash
            d = i[0]
            pr = i[1]
            po = i[2]
            ip = i[3]
            # using continue so that time is not wasted moving on to other components of each Packetif one of them is found to be incorrect
            #start by making sure that the direction is correct
            if(direction != d):
                continue
            else:
                # if the direction is correct then the protocol is checked
                if(protocol != pr):
                    continue
                else:
                    # if the protocol and the direction are correct then the port is checked either for a range
                    # or for an exact value
                    if(len(po) == 2):
                        if(int(po[0]) <= port <= int(po[1])):
                            # the ip address is checked last in order to make sure that time is not wasted checking it if
                            # the other elements in the tuple are incorrect
                            if (self.ip_check(ip, ip_address)):
                                return True
                            else:
                                continue

                        else:
                            continue
                    else:
                        if(int(po[0]) != port):
                            continue
                        else:
                            if (self.ip_check(ip, ip_address)):
                                return True
                            else:
                                continue

        return False








fw = Firewall("test.csv")
# print(fw.accept_packet("outbound", "udp", 80, "499.0.1.2"))
# print(fw.accept_packet("inbound", "tcp", 80, "192.168.1.2"))
# print(fw.accept_packet("inbound", "udp", 53, "192.168.2.1"))
# print(fw.accept_packet("inbound", "tcp", 81, "192.168.1.2"))
print(fw.accept_packet("inbound", "udp", 24, "52.12.48.92"))


