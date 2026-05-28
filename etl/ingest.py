"""
etl/ingest.py
─────────────
Responsible for loading raw events from the data source (sample_events.json).
This is the entry point of the pipeline — it reads the file, parses the JSON,
and returns a list of raw dictionaries ready for normalization.
 
Nothing is validated or transformed here. Ingest does one job: load the data.
"""

import json
from pathlib import Path
from loguru import logger

def load_events(filepath: str) -> list[dict]:
    """
    Load raw events from a JSON file.
 
    Args:
        filepath: Path to the JSON file (from config.yaml → data.sample_file)
 
    Returns:
        List of raw event dictionaries.
 
    Raises:
        FileNotFoundError: If the file does not exist at the given path.
        ValueError: If the file is not valid JSON or is not a JSON array.
    """
    path = Path(filepath)

    if not path.exists():
        logger.error(f"Data file not found: {filepath}")
        raise FileNotFoundError(f"Data file not found: {filepath}")
    
    logger.info(f"Loading events from: {filepath}")

    with open(path, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON: {e}")
            raise ValueError(f"Invalid JSON in file {filepath}: {e}")
        
    if not isinstance(data, list):
        raise ValueError(f"Expected a JSON array in {filepath}, got {type(data).__name__}")
    
    logger.info(f"Loaded {len(data)} raw events")
    return data
    