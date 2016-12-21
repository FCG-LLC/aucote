"""
This script provides decoder for kudu messages:

Usage:
    python decode_kudu.py --file <filepath> --msg <kudu message as hexstring>

One of two arguments (file, msg) is obligatory

"""
import argparse

from database.serializer import Serializer


def main():
    """
    Main apllication. Decode

    Returns:
        None
    """
    parser = argparse.ArgumentParser(description='Decoding kudu message')
    parser.add_argument("--file", help="Path for file with kudu messages")
    parser.add_argument("--msg", help="Kudu message")
    args = parser.parse_args()

    if not args.file and not args.msg:
        print("Usage: python decode_kudu.py --file <filepath> --msg <kudu message as hexstring>\n"
              "One of arguments is obligatory")
        exit(1)

    if args.msg:
        print("\n==========DECODING MESSAGE==========\n")
        data = Serializer.deserialize_port_vuln(args.msg.strip())
        for key in data.keys():
            print(key, data[key])

    if args.file:
        print("\n==========PARSING FILE {0}==========\n".format(args.file))
        with open(args.file.strip()) as f:
            lines = f.readlines()
            results = []
            for line in lines:
                results.append(Serializer.deserialize_port_vuln(line.strip()))

            results_by_key = []
            for result in results:
                results_by_key.append(result['key'])
                print("==========")
                for key in result.keys():
                    print(key, result[key])


            print(len(results_by_key))
            print(len(set(results_by_key)))

if __name__ == '__main__':
    main()