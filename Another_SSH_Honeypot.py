import paramiko, os, socket, logging, argparse, threading, subprocess, geoip2.database

PORT = 0
HOST = ""
BANNER = ""
DB_country = ""
DB_city = ""

atc_user = ""
# stored_ip = ""

logger = logging.getLogger("FE SSH Honeypot Log File")
logger.setLevel(logging.INFO)
logger.addHandler(logging.FileHandler("FE SSH Honeypot.log"))


def defined_variables(aegs):
    global HOST, PORT, BANNER, DB_city, DB_country
    HOST = aegs.h
    PORT = aegs.p
    BANNER = aegs.b
    DB_city = aegs.c
    DB_country = aegs.a


class My_FE_SSH_Honeypot(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            logger.info(
                "Channel Request for a "
                + str(kind)
                + " with a Channel ID of "
                + str(chanid)
                + "\n"
            )
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    # SSH server accepts pty channels
    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ):
        return True

    # SSH server accepts shell channels
    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    # SSH server will allow only passwords and publickeys for authentication
    def get_allowed_auths(self, username):
        return "password, publickey"

    # all passwords are accepting regardless if they are wrong
    def check_auth_password(self, username, password):
        global atc_user
        atc_user = username

        logger.info(
            username + " logged into the SSH server with the password: " + password
        )
        return paramiko.AUTH_SUCCESSFUL

    # all public keys are accepted regardless if they are wrong
    def check_auth_publickey(self, username, key):
        logger.info(
            username + "logged into the SSH server using the public key: " + key
        )
        return paramiko.AUTH_SUCCESSFUL

    # allows all commands entered in to the shell to be executed
    # add difference in operating systems too later; probably for commandline argument
    def check_channel_exec_request(self, channel, command):
        return True

    def get_banner(self):
        return bytes(BANNER + "\n", "utf-8"), b"en"


def get_ip_address_loc(ip_clie):
    logger_ip = logging.getLogger("FE IP Log File")
    logger_ip.setLevel(logging.INFO)
    logger_ip.addHandler(logging.FileHandler("SSH_Honeypot_IP.log"))
    try:
        if DB_city != "":
            with geoip2.database.Reader(DB_city) as reader:
                response = reader.city(ip_clie)
                logger_ip.info(
                    ip_clie + " located in the city/town of " + response.city.name
                )
                logger_ip.info(ip_clie + " postal code" + response.postal.code)
                logger_ip.info(
                    ip_clie
                    + "located at latitude "
                    + response.location.latitude
                    + " and longitude "
                    + response.location.longitude
                )
        if DB_country != "":
            with geoip2.database.Reader(DB_country) as reader:
                response2 = reader.country(ip_clie)
                logger.info(ip_clie + " located in " + response2.country.name)
    except geoip2.errors.AddressNotFoundError:
        logger_ip.info(
            ip_clie
            + " is not in the database. It it possible that it is a private IP address."
        )


def handle_server_start():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as ssh_sock:
        ssh_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        ssh_sock.bind((HOST, PORT))
        ssh_sock.listen(15)

        # global stored_ip

        while True:
            ssh_conn, ssh_addr = ssh_sock.accept()
            store_ip = ssh_addr[0]
            print("SSH Server Listening on:", ssh_addr)
            logger.info(f"Connection from: {ssh_addr}")
            ssh_transport_req = paramiko.Transport(ssh_conn)
            ssh_transport_req.add_server_key(paramiko.RSAKey.generate(2048))
            ssh_server_c = My_FE_SSH_Honeypot()
            ssh_transport_req.start_server(server=ssh_server_c)

            # everything is working above this comment in this function

            opened_channel = ssh_transport_req.accept()
            cmd = b""
            opened_channel.send("\r\n" + f"{atc_user}~$ ")
            while True:
                try:
                    # opened_channel.send(f"${atc_user}~ ")
                    command = opened_channel.recv(1024)
                    if command.endswith(b"\r") == False:
                        opened_channel.send(command)
                        cmd = cmd + command
                        print(f"commd: {cmd}")
                    if command.endswith(b"\x7f"):
                        opened_channel.send(b"\b \b")
                        cmd = cmd[:-2]
                        print(f"commd: {cmd}")
                    if command.endswith(b"\r"):
                        cmd_exc = subprocess.check_output(
                            cmd.decode(), stderr=subprocess.STDOUT, shell=True
                        )
                        opened_channel.send(b"\r\n" + cmd_exc)
                        logger.info(atc_user + f" entered the command: {cmd.decode()} ")
                        cmd = b""
                        opened_channel.send("\r\n" + f"{atc_user}~$ ")
                    if cmd == b"exit":
                        logger.info(atc_user + f" entered the command: {cmd.decode()} ")
                        if DB_city != "" or DB_country != "":
                            get_ip_address_loc(store_ip)
                        opened_channel.send("\r\n" + "Bye!!!!" + "\r\n")
                        break
                except KeyboardInterrupt():
                    break
            opened_channel.close()
            ssh_transport_req.close()


if __name__ == "__main__":
    my_parser = argparse.ArgumentParser(
        prog="FE Project", description="SSH Honeypot FE"
    )
    my_parser.add_argument("--h", type=str, default="0.0.0.0", help="Host")
    my_parser.add_argument("--p", type=int, default=2020, help="Port")
    my_parser.add_argument(
        "--b", type=str, default="Welcome and Such!! ", help="Banner Message"
    )
    my_parser.add_argument(
        "--c", type=str, required=False, help="GeoIP City DB", default=""
    )
    my_parser.add_argument(
        "--a", type=str, required=False, help="GeoIP Country DB", default=""
    )
    aegs = my_parser.parse_args()
    defined_variables(aegs)
    handle_server_start()
