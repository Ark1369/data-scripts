# CBZ Webp Convertor

webp_converter.py - Script to Batch Convert files from JPG/PNG to WEBP format for effecient storage.
![image](https://github.com/user-attachments/assets/6edd6f21-5f96-4392-874a-d21b5de53813)
- To install Dependencies - Run the following command in terminal
    - `pip install pillow opencv-python tkinterdnd2 tqdm`
- To Run Script run the following command in terminal in the folder script is placed in
    - `python webp_converter.py`
- or let UV to handle all dependencies itself, in terminal run following command
    - `pip install uv` (Once)
    - `uv run webp_converter`

**Features**

- Fully functioning GUI.
- Allows Drag and Drop Folders and CBZ - individually or multiple at once.
- Can convert to WEBP/JPEG and can specify quality in GUI. (Default Quality is 80)
    - To change default quality edit `quality_var = tk.StringVar(value="80")` to desired quality. 
- Preview feature - Randomly samples 3 or more images from the target CBZ and converts them in memory to showcase how size would look like (Useful to check before converting Large Volumes/Omnibus).
    - Under `def preview_estimate():`  change `sample_images = random.sample(image_files, min(3, len(image_files)))` from 3 to desired image count.
    - Will show no images if target files are already all webp.
- Backups incase of abrupt data errors.
- Restore Original file if -
    - Converted File > 105% of Original File.
    - The converted files <100 KB
    - Converted File Image Count < Original File Image Count.  
- Skips processing CBZ if all target files are already WEBP saving I/O.
- Splits Original images that are above the Max Dimension Set in GUI and renumbers them to prevent WEBP conversion failing. (Default Max Dimension is 8000 Width or Height)
    - To change default Max Dimension edit `max_dim_var = tk.StringVar(value="8000")` to desired dimension. WEBP limits are 16383 x 16383 Pixels.
    - Informs in GUI about images spilt.
- Displays Before and After Sizes per file, per folder processed and at the end for full batch.
- Pause feature that ends the current Job after ongoing file is processed.
- File Hashing to prevent re-conversion and aid in file integrity.
- Parallael Processing to make best use out of your CPU cores for fast conversions.
