#To install Dependencies - Run the following command in terminal
#pip install pillow opencv-python tkinterdnd2
#To Run Script run the following command in terminal in the folder script is placed in
#python webp_converter.py

import os
import shutil
import zipfile
import tempfile
import hashlib
import time
import threading
import tkinter as tk
from tkinterdnd2 import TkinterDnD
from tkinter import filedialog, messagebox, ttk
from concurrent.futures import (
    ThreadPoolExecutor,
    ProcessPoolExecutor,
    as_completed,
)
from PIL import Image
from tqdm import tqdm
import logging
import random
import io
import re


# Configure logging for the application
logging.basicConfig(
    filename="conversion_gui_log.txt",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


# Compute SHA-256 hash of a file in chunks to avoid large memory usage
def compute_file_hash(filepath, chunk_size=65536):
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


# Human-readable formatting of byte sizes into MB
def format_size(size_in_bytes):
    size_in_mb = size_in_bytes / (1024 * 1024)
    return f"{size_in_bytes} bytes ({size_in_mb:.2f} MB)"


# Count files in a directory matching given extensions
def count_files(directory, extensions):
    return sum(
        1
        for root, _, files in os.walk(directory)
        for file in files
        if file.lower().endswith(extensions)
    )


# Extract leading integer from filename for proper sorting
def extract_sort_key(name):
    # Extract leading integer (e.g., from '0012_image_001.webp')
    match = re.match(r"(\d+)", name)
    return int(match.group(1)) if match else 0


# Safely remove a file, logging any failure
def safe_remove(path):
    try:
        os.remove(path)
    except Exception as e:
        logging.warning(f"Could not remove {path}: {e}")


# Safely remove a directory tree, logging any failure
def safe_rmtree(path):
    try:
        shutil.rmtree(path)
    except Exception as e:
        logging.warning(f"Could not remove directory {path}: {e}")


# Calculate total size of all files in a folder
def get_folder_size(folder):
    total_size = 0
    for dirpath, _, filenames in os.walk(folder):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            if os.path.isfile(fp):
                total_size += os.path.getsize(fp)
    return total_size


# Split an image into tiles if it exceeds the maximum dimension limit
def split_large_image(img, base_name, fmt, quality, max_dim):
    w, h = img.size
    tiles = []
    x_tiles = (w + max_dim - 1) // max_dim
    y_tiles = (h + max_dim - 1) // max_dim
    count = 1
    for i in range(x_tiles):
        for j in range(y_tiles):
            left = i * max_dim
            upper = j * max_dim
            right = min(left + max_dim, w)
            lower = min(upper + max_dim, h)
            crop = img.crop((left, upper, right, lower))
            buf = io.BytesIO()
            crop.save(buf, format=fmt, quality=quality)
            tiles.append(
                (f"{base_name}_{count:03d}.{fmt.lower()}", buf.getvalue())
            )
            count += 1
    return tiles


# Convert raw image bytes to desired format, splitting if too large
def convert_image_from_bytes(image_bytes, base_name, format, quality, max_dim):
    try:
        img = Image.open(io.BytesIO(image_bytes))
        img = img.convert("RGB")  # Ensure RGB mode
        # If dimensions exceed limit, split into tiles
        if img.width > max_dim or img.height > max_dim:
            return split_large_image(img, base_name, format, quality, max_dim)
        # Otherwise, convert and return single image
        buf = io.BytesIO()
        img.save(buf, format=format, quality=quality)
        return [(f"{base_name}.{format.lower()}", buf.getvalue())]
    except Exception as e:
        error_msg = str(e)
        logging.error(f"Image conversion error: {e}")
        return []


# Read file bytes, returning tuple for pool processing
def read_file_bytes(f):
    with open(f, "rb") as fp:
        return (f, fp.read())


stop_event = threading.Event()


# Process a single CBZ archive: extract, convert images, validate, and repackage
def process_cbz(
    cbz_file,
    output_callback,
    img_format,
    img_quality,
    max_dim,
    result_sizes=None,
):
    tile_info_log = []
    base_name = os.path.splitext(os.path.basename(cbz_file))[0].strip()
    done_marker = cbz_file + ".done"
    # Skip if already marked done
    if os.path.exists(done_marker):
        output_callback(f"[Skipped] Already processed: {base_name}")
        return

    # If converting to WEBP and archive already contains only WEBPs, skip
    if img_format.upper() == "WEBP":
        try:
            with zipfile.ZipFile(cbz_file, "r") as zip_ref:
                image_files = [
                    f
                    for f in zip_ref.namelist()
                    if f.lower().endswith((".jpg", ".jpeg", ".png", ".webp"))
                ]
                if image_files and all(
                    f.lower().endswith(".webp") for f in image_files
                ):
                    output_callback(
                        f"[Skipped] {base_name} already contains only WEBP images."
                    )
                    return
        except Exception as e:
            output_callback(f"[Error] Failed to inspect {base_name}: {e}")
            logging.error(f"Inspection error for {cbz_file}: {e}")
            return

    temp_dir = tempfile.mkdtemp(prefix=base_name + "_")
    backup_cbz = cbz_file + ".bak"
    before_size = os.path.getsize(cbz_file)

    try:
        shutil.copy(cbz_file, backup_cbz)
        with zipfile.ZipFile(cbz_file, "r") as zip_ref:
            zip_ref.extractall(temp_dir)

        # Collect all image file paths
        image_files = [
            os.path.join(dp, f)
            for dp, _, fs in os.walk(temp_dir)
            for f in fs
            if f.lower().endswith((".jpg", ".jpeg", ".png"))
        ]

        ext = "jpg" if img_format.upper() == "JPEG" else img_format.lower()
        output_images = []

        # Use thread pool to convert images in parallel
        with ThreadPoolExecutor() as executor:
            futures = []
            for fpath in image_files:
                base_img_name = os.path.splitext(os.path.basename(fpath))[0]
                with open(fpath, "rb") as img_file:
                    img_bytes = img_file.read()
                futures.append(
                    executor.submit(
                        convert_image_from_bytes,
                        img_bytes,
                        base_img_name,
                        img_format,
                        img_quality,
                        max_dim,
                    )
                )

            from concurrent.futures import as_completed

            # Collect conversion results with a progress bar
            for future in tqdm(
                as_completed(futures),
                total=len(futures),
                desc=f"Converting {base_name}",
                unit="img",
            ):
                results = future.result()
                base_img_name = (
                    results[0][0].rsplit(".", 1)[0].rsplit("_", 1)[0]
                    if results
                    else "unknown"
                )
                if len(results) > 1:
                    tile_info_log.append(
                        f"  - Split '{base_img_name}' into {len(results)} tiles due to WebP size limit."
                    )
                if not results:
                    continue
                output_images.extend(results)

        # Remove original extracted images
        for f in image_files:
            safe_remove(f)

        # Sort and rename output images to preserve order and avoid name clashes
        output_images.sort(key=lambda x: extract_sort_key(x[0]))

        from collections import defaultdict

        name_counters = defaultdict(int)

        for name, content in output_images:
            base = os.path.splitext(name)[0]
            name_counters[base] += 1
            if name_counters[base] > 1:
                out_name = f"{base}_{name_counters[base]:02d}.{ext}"
            else:
                out_name = f"{base}.{ext}"
            out_path = os.path.join(temp_dir, out_name)
            with open(out_path, "wb") as f:
                f.write(content)

        # Create new CBZ archive from converted images
        new_cbz_path = os.path.join(
            os.path.dirname(cbz_file), base_name + "_converted.zip"
        )
        shutil.make_archive(new_cbz_path.replace(".zip", ""), "zip", temp_dir)
        safe_rmtree(temp_dir)

        after_size = os.path.getsize(new_cbz_path)

        # Preserve original if converted archive is suspiciously small
        if after_size < 100 * 1024:
            output_callback(
                f"[Preserved] {base_name} not replaced due to suspiciously small size (<100KB).\nBefore: {format_size(before_size)}\nAfter: {format_size(after_size)}"
            )
            os.remove(new_cbz_path)
            os.remove(cbz_file)
            os.rename(backup_cbz, cbz_file)
            return

        # Validate image counts to detect loss
        with zipfile.ZipFile(new_cbz_path, "r") as converted_zip:
            converted_count = sum(
                1
                for f in converted_zip.namelist()
                if f.lower().endswith((".jpg", ".jpeg", ".webp"))
            )

        if converted_count < len(image_files):
            output_callback(
                f"[Preserved] {base_name} not replaced due to image loss.\nOriginal Count: {len(image_files)} | Converted: {converted_count}"
            )
            os.remove(new_cbz_path)
            os.remove(cbz_file)
            os.rename(backup_cbz, cbz_file)
            return

        # Check for size increase above threshold
        size_increase_percent = (
            ((after_size - before_size) / before_size) * 100
            if after_size > before_size
            else 0
        )

        if size_increase_percent >= 5:
            output_callback(
                f"[Preserved] {base_name} not replaced due to size increase.\nBefore: {format_size(before_size)}\nAfter: {format_size(after_size)}"
            )
            # Replace original with converted archive
            os.remove(new_cbz_path)
            os.remove(cbz_file)
            os.rename(backup_cbz, cbz_file)
        else:
            os.remove(cbz_file)
            os.rename(new_cbz_path, cbz_file)
            os.remove(backup_cbz)
            with open(done_marker, "w") as f:
                f.write("done")
            # Report any tile splitting events
            if tile_info_log:
                output_callback(
                    "[Info] The following images were split into multiple tiles due to size limits:"
                    + "".join(tile_info_log)
                )
                for log_entry in tile_info_log:
                    logging.info(f"[Tiling] {log_entry}")
            output_callback(
                f"[Success] {base_name} processed successfully.\nBefore: {format_size(before_size)}\nAfter: {format_size(after_size)}"
            )

        # Record sizes if requested for summary
        if result_sizes is not None:
            result_sizes.append((before_size, after_size))

    except Exception as e:
        # Handle critical errors and attempt to restore backup
        output_callback(f"[Error] {base_name}: {e}")
        logging.error(f"Critical error in {cbz_file}: {e}")
        if os.path.exists(backup_cbz):
            shutil.move(backup_cbz, cbz_file)
        safe_rmtree(temp_dir)

    finally:
        # Clean up done marker on stop
        if os.path.exists(done_marker) and stop_event.is_set():
            safe_remove(done_marker)


# ---- GUI Section ----


# Runs the main GUI application loop.
# Allows folder selection, drag-and-drop CBZ files, conversion controls, and output log display.
def run_gui():
    selected_cbz_files = []

    # Opens a folder selection dialog and lists all CBZ files inside for processing.
    def choose_folder():
        folder = filedialog.askdirectory()
        if folder:
            cbz_files = [
                os.path.join(dp, f)
                for dp, _, fs in os.walk(folder)
                for f in fs
                if f.lower().endswith(".cbz")
            ]
            if not cbz_files:
                messagebox.showinfo(
                    "No Files", "No CBZ files found in selected folder."
                )
                return
            selected_cbz_files.clear()
            selected_cbz_files.extend(cbz_files)
            file_list.delete(0, tk.END)
            for f in cbz_files:
                file_list.insert(tk.END, os.path.basename(f))

    # Appends messages to the GUI output textbox for user feedback.
    def output_callback(message):
        root.update_idletasks()
        output_text.insert(tk.END, message + "\n")
        output_text.see(tk.END)

    # Starts conversion processing in a background thread, iterating over selected CBZ files grouped by folder,updating GUI controls accordingly.
    def start_processing():
        if not selected_cbz_files:
            messagebox.showerror("No Files", "No CBZ files selected.")
            return
        stop_event.clear()
        start_btn.config(state="disabled")
        pause_btn.config(state="normal")
        fmt = format_var.get()
        try:
            quality = int(quality_var.get())
        except ValueError:
            quality = 80

        try:
            max_dim = int(max_dim_var.get())
        except ValueError:
            max_dim = 16383

        def threaded():
            start_time = time.time()
            folder_map = {}

            for cbz in selected_cbz_files:
                folder = os.path.dirname(cbz)
                folder_map.setdefault(folder, []).append(cbz)

            grand_total_before = 0
            grand_total_after = 0

            for folder, cbz_list in folder_map.items():
                folder_before = 0
                folder_after = 0
                output_callback(f"\n--- Processing Folder: {folder} ---")
                for cbz in cbz_list:
                    if stop_event.is_set():
                        break
                    result_sizes = []
                    process_cbz(
                        cbz,
                        output_callback,
                        fmt,
                        quality,
                        max_dim,
                        result_sizes,
                    )
                    for b, a in result_sizes:
                        folder_before += b
                        folder_after += a
                        grand_total_before += b
                        grand_total_after += a

                output_callback(
                    f"[Folder Summary] {folder}\n  Total Before: {format_size(folder_before)}\n  Total After: {format_size(folder_after)}\n"
                )

            output_callback(
                f"\n[Batch Summary] All done in {time.time() - start_time:.2f} seconds.\nTotal Before: {format_size(grand_total_before)}\nTotal After: {format_size(grand_total_after)}"
            )

            start_btn.config(state="normal")
            pause_btn.config(state="disabled")
            for cbz in selected_cbz_files:
                done_marker = cbz + ".done"
                safe_remove(done_marker)

        threading.Thread(target=threaded).start()

    # Sets a flag to pause the ongoing processing gracefully.
    def pause_processing():
        stop_event.set()
        output_callback("\n[Paused] Processing will halt after current file.")

    # Handles drag-and-drop of CBZ files or folders, updating file list.
    def drag_and_drop(event):
        try:
            files = root.tk.splitlist(event.data)
            cbz_only = []
            for f in files:
                f_clean = f.strip("{}")
                if os.path.isdir(f_clean):
                    for dp, _, fs in os.walk(f_clean):
                        for file in fs:
                            if file.lower().endswith(".cbz"):
                                cbz_only.append(os.path.join(dp, file))
                elif f_clean.lower().endswith(".cbz"):
                    cbz_only.append(f_clean)
            if cbz_only:
                selected_cbz_files.clear()
                selected_cbz_files.extend(cbz_only)
                file_list.delete(0, tk.END)
                for f in cbz_only:
                    file_list.insert(tk.END, os.path.basename(f))
        except Exception as e:
            output_callback(f"Drag-and-drop error: {e}")

    # Estimates size savings by sampling a few images per CBZ, showing rough before/after sizes in the GUI.
    def preview_estimate():
        if not selected_cbz_files:
            messagebox.showinfo("No Files", "No CBZ files selected.")
            return

        fmt = format_var.get()
        try:
            quality = int(quality_var.get())
        except ValueError:
            quality = 80

        output_text.insert(tk.END, "\n--- Preview Estimates ---\n")
        total_original = 0
        total_estimated = 0

        for cbz in selected_cbz_files:
            try:
                with zipfile.ZipFile(cbz, "r") as zip_ref:
                    image_files = [
                        f
                        for f in zip_ref.namelist()
                        if f.lower().endswith((".jpg", ".jpeg", ".png"))
                    ]

                    if not image_files:
                        output_text.insert(
                            tk.END,
                            f"{os.path.basename(cbz)}: No images found.\n",
                        )
                        continue

                    sample_images = random.sample(
                        image_files, min(3, len(image_files))
                    )
                    original_total = 0
                    converted_total = 0

                    for img_name in sample_images:
                        with zip_ref.open(img_name) as img_file:
                            from io import BytesIO

                            img_bytes = img_file.read()
                            original_total += len(img_bytes)
                            img = Image.open(io.BytesIO(img_bytes))

                            buf = BytesIO()
                            img.convert("RGB").save(buf, fmt, quality=quality)
                            converted_total += buf.tell()

                    ratio = (
                        converted_total / original_total
                        if original_total
                        else 1.0
                    )
                    actual_cbz_size = os.path.getsize(cbz)
                    est_after = actual_cbz_size * ratio

                    total_original += actual_cbz_size
                    total_estimated += est_after

                    output_text.insert(
                        tk.END,
                        f"{os.path.basename(cbz)}:\n  Before: {format_size(actual_cbz_size)}\n  Estimated After: {format_size(est_after)}\n",
                    )
            except Exception as e:
                output_text.insert(
                    tk.END, f"{os.path.basename(cbz)}: Preview error - {e}\n"
                )
                logging.error(f"Preview error for {cbz}: {e}")

        if total_original > 0:
            savings = (
                (total_original - total_estimated) / total_original
            ) * 100
            output_text.insert(
                tk.END, f"\nEstimated Average Savings: {savings:.2f}%\n"
            )
        output_text.see(tk.END)

    # Setup GUI window, widgets, and event bindings here.
    root = TkinterDnD.Tk()
    root.title("CBZ Image Converter")
    root.geometry("750x550")

    frm = tk.Frame(root)
    frm.pack(pady=5)

    select_btn = tk.Button(frm, text="Select Folder", command=choose_folder)
    select_btn.grid(row=0, column=0, padx=5)

    tk.Label(frm, text="Output Format:").grid(row=0, column=1)
    format_var = tk.StringVar(value="WEBP")
    format_menu = ttk.Combobox(
        frm, textvariable=format_var, values=["WEBP", "JPEG"], width=8
    )
    format_menu.grid(row=0, column=2)

    tk.Label(frm, text="Quality:").grid(row=0, column=3)
    quality_var = tk.StringVar(value="80")
    quality_entry = tk.Entry(frm, textvariable=quality_var, width=5)
    quality_entry.grid(row=0, column=4)

    tk.Label(frm, text="Max Dim:").grid(row=0, column=5)
    max_dim_var = tk.StringVar(value="8000")
    max_dim_entry = tk.Entry(frm, textvariable=max_dim_var, width=6)
    max_dim_entry.grid(row=0, column=6)

    start_btn = tk.Button(frm, text="Start", command=start_processing)
    start_btn.grid(row=0, column=7, padx=5)

    pause_btn = tk.Button(
        frm, text="Pause", command=pause_processing, state="disabled"
    )
    pause_btn.grid(row=0, column=8, padx=5)

    preview_btn = tk.Button(frm, text="Preview", command=preview_estimate)
    preview_btn.grid(row=0, column=9, padx=5)

    file_list = tk.Listbox(root, height=5)
    file_list.pack(fill=tk.X, padx=10, pady=5)

    output_text = tk.Text(root, wrap=tk.WORD)
    output_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    try:
        import tkinterdnd2 as tkdnd

        root.tk.call("package", "require", "tkdnd")
        root.drop_target_register(tkdnd.DND_FILES)
        root.dnd_bind("<<Drop>>", drag_and_drop)
    except Exception as e:
        logging.warning(f"tkinterdnd2 not available or failed: {e}")

    root.mainloop()


if __name__ == "__main__":
    run_gui()
