import argparse
import pickle
import sys
from glomar import GlomarStore, CreateGlomarStore


KB = 1024
DEFAULT_BLOCK_SIZE = 4 * KB


class GlomarCLI:
    @staticmethod
    def create(file, n_blocks, block_size):
        cbs = CreateGlomarStore(n_blocks, block_size=block_size)
        with open(file, 'wb') as f:
            pickle.dump(cbs, f)

    @staticmethod
    def add(store_file, key, file):
        with open(store_file, 'rb') as f:
            store = pickle.load(f)

        with open(file, 'rb') as f:
            store.add(bytes(key, 'utf-8'), f.read())

        with open(store_file, 'wb') as f:
            pickle.dump(store, f)

    @staticmethod
    def get(store_file, key, block_size):
        with open(store_file, 'rb') as f:
            store = GlomarStore(f.read(), block_size=block_size)
        res = store.get(bytes(key, 'utf-8'))
        if res:
            sys.stdout.buffer.write(res)

    @staticmethod
    def pack(store_file, out_file):
        with open(store_file, 'rb') as f:
            store = pickle.load(f)
        with open(out_file, 'wb') as f:
            f.write(store.pack())


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='command')
    # Create a store
    create_p = subparsers.add_parser('create')
    create_p.add_argument('file')
    create_p.add_argument('--n-blocks', type=int, default=1000)
    create_p.add_argument('--block-size', type=int, default=DEFAULT_BLOCK_SIZE)
    # Add a file to a store
    add_p = subparsers.add_parser('add')
    add_p.add_argument('store_file')
    add_p.add_argument('key')
    add_p.add_argument('file')
    # Output a packed file store
    pack_p = subparsers.add_parser('pack')
    pack_p.add_argument('store_file')
    pack_p.add_argument('out_file')
    # Get a file from a store
    get_p = subparsers.add_parser('get')
    get_p.add_argument('store_file')
    get_p.add_argument('key')
    get_p.add_argument('--block-size', type=int, default=DEFAULT_BLOCK_SIZE)

    args = parser.parse_args()

    match args.command:
        case 'create':
            GlomarCLI.create(args.file, args.n_blocks, args.block_size)
        case 'add':
            GlomarCLI.add(args.store_file, args.key, args.file)
        case 'pack':
            GlomarCLI.pack(args.store_file, args.out_file)
        case 'get':
            GlomarCLI.get(args.store_file, args.key, args.block_size)
        case _:
            pass


if __name__ == "__main__":
    main()
