from glomar import GlomarStore, CreateGlomarStore


def main():
    key = b'hello'
    f = open('/etc/passwd', 'rb').read()
    cbs = CreateGlomarStore(1000)
    cbs.add(key, f)

    bs = GlomarStore(cbs.pack())
    print(bs.get(key))


if __name__ == "__main__":
    main()
