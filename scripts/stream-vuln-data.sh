LOCAL_FILE="vulnerability_parsed_report.json"
CONTAINER_PATH="/app/scan_file/vulnerability_report.json"
POD_NAME="<POD_NAME>" # Make sure this variable is defined earlier in your script!

echo "--- 2. Streaming Filtered Data to Pod ---"

# CORRECTED: The whole command and redirection are now inside quotes, 
# ensuring they are interpreted by the remote shell (sh -c).
cat "$LOCAL_FILE" | kubectl exec -i -n flask-app "$POD_NAME" -- sh -c "cat > \"$CONTAINER_PATH\""

echo "✅ Final data transfer complete."