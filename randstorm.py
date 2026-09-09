import base58
import coincurve
import hashlib
import itertools
import os
import random
import time
from multiprocessing import Pool
from rich.console import Console

console = Console()

Randstorm = """
██████╗░░█████╗░███╗░░██╗██████╗░░██████╗████████╗░█████╗░██████╗░███╗░░░███╗
██╔══██╗██╔══██╗████╗░██║██╔══██╗██╔════╝╚══██╔══╝██╔══██╗██╔══██╗████╗░████║
██████╔╝███████║██╔██╗██║██║░░██║╚█████╗░░░░██║░░░██║░░██║██████╔╝██╔████╔██║
██╔══██╗██╔══██║██║╚████║██║░░██║░╚═══██╗░░░██║░░░██║░░██║██╔══██╗██║╚██╔╝██║
██║░░██║██║░░██║██║░╚███║██████╔╝██████╔╝░░░██║░░░╚█████╔╝██║░░██║██║░╚═╝░██║
╚═╝░░╚═╝╚═╝░░╚═╝╚═╝░░╚══╝╚═════╝░╚═════╝░░░░╚═╝░░░░╚════╝░╚═╝░░╚═╝╚═╝░░░░░╚═╝
"""

class SecureRandom:
    def __init__(self, seed):
        self.rng_pool = []
        self.rng_pptr = 0
        self.rng_psize = 32
        random.seed(seed)
        for _ in range(self.rng_psize):
            self.rng_pool.append(random.randint(0, 255))

    def rng_get_byte(self):
        if self.rng_pptr >= len(self.rng_pool):
            self.rng_pptr = 0
            self.rng_pool = [random.randint(0, 255) for _ in range(self.rng_psize)]
        byte = self.rng_pool[self.rng_pptr]
        self.rng_pptr += 1
        return byte

    def rng_get_bytes(self, length):
        result = bytearray(length)
        for i in range(length):
            result[i] = self.rng_get_byte()
        return result

def generate_compressed_P2P_address(private_key_hex):
    private_key_bytes = bytes.fromhex(private_key_hex)
    public_key = coincurve.PrivateKey(private_key_bytes).public_key.format(compressed=True)
    public_key_hash = hashlib.new('ripemd160', hashlib.sha256(public_key).digest()).hexdigest()
    
    extended_public_key_hash = '00' + public_key_hash
    checksum = hashlib.sha256(hashlib.sha256(bytes.fromhex(extended_public_key_hash)).digest()).hexdigest()[:8]
    p2pkh_address = base58.b58encode(bytes.fromhex(extended_public_key_hash + checksum))
    return p2pkh_address.decode()

def process_worker(args):
    seed, target_address = args
    process_start_time = time.time()
    
    secure_rng = SecureRandom(seed)

    # Scans endlessly with no upper limit
    for i in itertools.count(1):
        try:
            random_bytes = secure_rng.rng_get_bytes(32)
            private_key = random_bytes.hex()

            p2pkh_address = generate_compressed_P2P_address(private_key)

            if p2pkh_address == target_address:
                print(f"\n[MATCH FOUND] Seed: {seed} | Private Key: {private_key}\n")
                with open("matched_private_keys.txt", "a") as file:
                    file.write(f"Seed: {seed} | Private Key: {private_key}\n")

            # Displays progress per process every 50,000 keys generated
            if i % 50000 == 0:
                elapsed = time.time() - process_start_time
                speed = i / elapsed if elapsed > 0 else 0
                print(f"[Worker Seed {seed}] Keys Scanned: {i:,} | Speed: {speed:.2f} Keys/s")

        except KeyboardInterrupt:
            break

if __name__ == '__main__':
    console.print(Randstorm)
    
    num_processes = 6
    target_address = os.environ.get("TARGET_ADDRESS", "1DGwqAM8mV4aJVPidoBp9Zfz8GKhAzLkma")

    print(f"Searching for: \033[93m{target_address}\033[0m")
    print(f"Workers: {num_processes} | Mode: Infinite Loop\n")

    start_seed = 1393635661000
    seeds = [start_seed + i for i in range(num_processes)]
    
    tasks = [(seed, target_address) for seed in seeds]

    try:
        with Pool(num_processes) as pool:
            pool.map(process_worker, tasks)
    except KeyboardInterrupt:
        print("\n[!] Stopped by user.")
