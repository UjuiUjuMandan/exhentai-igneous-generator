import express from 'express';
import fetch from 'node-fetch';

const app = express();
app.use(express.json());

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  next();
});

app.get('/', async (req, res) => {
  try {
    const traceUrl = 'https://exhentai.org/cdn-cgi/trace';
    const response = await fetch(traceUrl);

    if (!response.ok) {
      return res.status(response.status).json({ error: 'Failed to fetch trace data' });
    }

    const traceData = await response.text();

    return res.type('text/plain').send(traceData);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: error.message });
  }
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
