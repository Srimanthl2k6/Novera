const express = require('express');
const app = express();

app.use(express.json());

// In-memory array to hold data (temporary storage)
const dataStore = [];

// POST route to insert data
app.post('/data', (req, res) => {
  const entry = {
    ...req.body,
    timestamp: new Date()
  };
  dataStore.push(entry);
  res.status(201).json(entry);
});

// GET route to fetch all stored data
app.get('/data', (req, res) => {
  res.json(dataStore);
});

// Health check route
app.get('/', (req, res) => {
  res.send('✅ Server is running (No DB)');
});

const PORT = process.env.PORT || 8000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
