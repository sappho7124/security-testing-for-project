# Use Node.js LTS as the base image
FROM node:18

# Set the working directory
WORKDIR /app

# Copy package.json and package-lock.json
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy the application code
COPY . .

# Expose the port the app runs on
EXPOSE 3000

# Run the tests (as part of the build process)
RUN npm install --save-dev jest supertest && npm test

# Start the application
CMD ["npm", "start"]
