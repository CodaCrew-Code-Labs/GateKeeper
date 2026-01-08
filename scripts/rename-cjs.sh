#!/bin/bash
# Rename .js files to .cjs in the dist/cjs directory and update imports
find dist/cjs -name "*.js" -type f | while read file; do
    # Update imports in the file to use .cjs extension
    sed -i '' 's/require("\.\//require(".\//' "$file"
    sed -i '' 's/\.js")/\.cjs")/g' "$file"
    # Rename the file
    mv "$file" "${file%.js}.cjs"
done