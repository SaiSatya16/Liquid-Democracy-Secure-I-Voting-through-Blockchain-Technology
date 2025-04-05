#!/bin/bash

# This works for next.js projects currently
# Put this in your root folder of your project
# run the command chmod +x get_code_context.sh
# then run ./get_code_context.sh

# Use the current directory as the project directory
project_dir=$(pwd)

# Use a fixed name for the output file in the current directory
output_file="${project_dir}/latest_code_context.txt"

# Check if the output file exists and remove it if it does
if [ -f "$output_file" ]; then
  rm "$output_file"
fi

# List of directories to look for
directories=("contracts" "static" "templates")

# List of directories to ignore
ignore_dirs=("data" "runs" "trained_models" ".git" "kwt" "node_modules")

# List of file types to ignore
ignore_files=( "*.db" "*.json" ".pyc" "*.ico" "*.png" "*.jpg" "*.jpeg" "*.gif" "*.svg" "*.pyc" "*.lock" "*.env" "*.DS_Store" "*.pdf" "*.zip" "*.gz" "*.tar" "*.tgz" "*.rar" "*.7z" "*.exe" "*.webp" "*.mp4" "*.mp3" "*.wav" "*.flac" "*.avi" "*.mov" "*.wmv" "*.wma" "*.flv" "*.mkv" "*.m4a" "*.m4v" "*.webm" "*.aac" "*.aiff" "*.oga" "*.ogg" "*.opus" "*.ra" "*.rm" "*.wav" "*.wma" "*.mpg" "*.mpeg" "*.m4v" "*.m4p" "*.m4b" "*.m4r" "*.m4a" "*.mp3" "*.mp2" "*.mp1" "*.ogg" "*.oga" "*.flac" "*.wav" "*.webm" "*.aac" "*.ac3" "*.wma" "*.opus" "*.ra" "*.rm" "*.mid" "*.midi" "*.oga" "*.weba" "*.3gp" "*.3g2" "*.m4v" "*.mp4" "*.mov" "*.avi" "*.ogv" "*.flv" "*.wmv" "*.mpeg" "*.mpg" "*.m4p" "*.m4v" "*.mp4" "*.avi" "*.wmv" "*.mov" "*.mkv" "*.flv" "*.webm" "*.m4a" "*.mp3" "*.wav" "*.flac" "*.aac" "*.ogg" "*.oga" "*.opus" "*.ra" "*.rm" "*.mid" "*.midi" "*.oga" "*.weba" "*.3gp" "*.3g2" "*.m4v" "*.mp4" "*.mov" "*.avi" "*.ogv" "*.flv" "*.sh" "*.txt" "*.pages")

# Recursive function to read files and append their content
read_files() {
  for entry in "$1"/*
  do
    if [ -d "$entry" ]; then
      # Check if the directory should be ignored
      dir_name=$(basename "$entry")
      if [[ " ${ignore_dirs[@]} " =~ " ${dir_name} " ]]; then
        continue
      fi
      # If entry is a directory, call this function recursively
      read_files "$entry"
    elif [ -f "$entry" ]; then
      # Check if the file type should be ignored
      should_ignore=false
      for ignore_pattern in "${ignore_files[@]}"; do
        if [[ "$entry" == $ignore_pattern ]]; then
          should_ignore=true
          break
        fi
      done

      # If the file type should not be ignored, append its relative path and content to the output file
      if ! $should_ignore; then
        relative_path=${entry#"$project_dir/"}
        echo "// File: $relative_path" >> "$output_file"
        cat "$entry" >> "$output_file"
        echo "" >> "$output_file"
      fi
    fi
  done
}

# Handle files in the root directory
for entry in "$project_dir"/*
do
  if [ -f "$entry" ]; then
    # Check if the file type should be ignored
    should_ignore=false
    for ignore_pattern in "${ignore_files[@]}"; do
      if [[ "$entry" == $ignore_pattern ]]; then
        should_ignore=true
        break
      fi
    done

    # If the file type should not be ignored, append its relative path and content to the output file
    if ! $should_ignore; then
      relative_path=${entry#"$project_dir/"}
      echo "// File: $relative_path" >> "$output_file"
      cat "$entry" >> "$output_file"
      echo "" >> "$output_file"
    fi
  fi
done

# Call the recursive function for each specified directory in the project directory
for dir in "${directories[@]}"; do
  if [ -d "${project_dir}/${dir}" ]; then
    read_files "${project_dir}/${dir}"
  fi
done