from dataclasses import dataclass, field
from datetime import datetime
import uuid

@dataclass
class Event:
    host : str
    source : str
    event_type : str
    severity : str
    description : str
    raw_data : dict
    id : str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp : str = field(default_factory=lambda: datetime.now().isoformat())
