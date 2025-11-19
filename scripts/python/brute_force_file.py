import multiprocessing
import subprocess
from tqdm import tqdm
from colorama import Fore, Style
import itertools


def generate_passwords(start, end, length, queue, chunk_size=1000):
    """Generate passwords and push them into a queue in chunks."""
    try:
        for chunk_start in range(start, end, chunk_size):
            chunk_end = min(chunk_start + chunk_size, end)
            passwords = [f"{num:0{length}}" for num in range(chunk_start, chunk_end)]
            queue.put(passwords)
        queue.put(None)  # Signal completion to consumers
    except Exception as e:
        print(f"Error in password generation: {e}")


def try_password(pdf_path, password):
    """Attempt to open the PDF with the given password using qpdf."""
    try:
        result = subprocess.run(
            ["qpdf", "--decrypt", f"--password={password}", pdf_path, "/dev/null"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return result.returncode == 0
    except Exception:
        return False


def brute_force_worker(pdf_path, queue, progress_queue, stop_event):
    """Consume passwords from the queue and attempt to brute force."""
    while not stop_event.is_set():
        passwords = queue.get()
        if passwords is None:
            queue.put(None)
            break

        for password in passwords:
            if stop_event.is_set():
                return
            if try_password(pdf_path, password):
                progress_queue.put(("found", password))
                stop_event.set()
                return
            progress_queue.put(("progress", 1))


def progress_listener(total, progress_queue, stop_event):
    """Listen for progress updates and update the progress bar."""
    spinner = itertools.cycle(["-", "/", "|", "\\"])
    with tqdm(total=total, desc="Brute-forcing", unit=" passwords") as pbar:
        while not stop_event.is_set():
            message = progress_queue.get()

            if message[0] == "found":
                pbar.close()
                print(f"{Fore.GREEN}Password found: {message[1]}{Style.RESET_ALL}")
                stop_event.set()
                break

            elif message[0] == "progress":
                pbar.set_description(
                    f"Brute-forcing {Fore.CYAN}{next(spinner)}{Style.RESET_ALL}"
                )
                pbar.update(message[1])


def parallel_brute_force(pdf_path, start, end, length, cores):
    """Coordinate producer-consumer brute force."""
    queue = multiprocessing.Queue(maxsize=cores * 2)
    progress_queue = multiprocessing.Queue()
    stop_event = multiprocessing.Event()

    producer = multiprocessing.Process(
        target=generate_passwords, args=(start, end, length, queue)
    )
    consumers = [
        multiprocessing.Process(
            target=brute_force_worker,
            args=(pdf_path, queue, progress_queue, stop_event)
        )
        for _ in range(cores)
    ]
    progress_monitor = multiprocessing.Process(
        target=progress_listener,
        args=(end - start, progress_queue, stop_event)
    )

    producer.start()
    for c in consumers:
        c.start()
    progress_monitor.start()

    producer.join()
    for c in consumers:
        c.join()

    progress_queue.put(("done", None))
    progress_monitor.join()


if __name__ == "__main__":
    # ------------------------------------------------------------
    # AUTOMATIC CONFIGURATION (no prompts, no arguments)
    # ------------------------------------------------------------

    pdf_path = "documents/finance/ipo/ARR_CONF_Lock.pdf"

    # Search numeric passwords 0000–9999
    start = 0
    end = 10000    # end is exclusive
    length = 4     # zero-pad to 4 digits

    cores = multiprocessing.cpu_count()

    print("\n=== Starting PDF Brute Force ===")
    print(f"PDF: {pdf_path}")
    print(f"Range: {start}–{end-1}")
    print(f"Length: {length} digits")
    print(f"CPU cores: {cores}\n")

    parallel_brute_force(pdf_path, start, end, length, cores)
