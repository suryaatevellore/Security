import argparse
import sys

def main(all_arguments):
    parser = argparse.ArgumentParser()
    parser.add_argument('--key', action="store", required=True,help="Enter the key value", dest="password", type=str)
    parser.add_argument('-l', help="Specify if the socket should be a listening socket", action="store_true", dest="listen")
    parser.add_argument("destination", nargs='?',help="Specify the Server IP Address", default='127.0.0.1')
    parser.add_argument("port", action="store", type=int)
    # parser.add_argument('-i',action="store",  default=None, help="Specify the input file", dest="inpfile")
    # parser.add_argument('-o',action="store", default=None, help="Specify the output file", dest='outfile')
    args = parser.parse_args()
    print(args)
    password = args.password
    listen = args.listen
    port = args.port
    server_address = args.destination
    #Use this for printing print(sys.stdin.read())
    # for something in sys.stdout:
    #     print(something)



if __name__ == "__main__":
    main(sys.argv[1:])

