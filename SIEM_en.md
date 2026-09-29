*Security Information and Event Management*
Software that enables the management, detection, and investigation of malicious actions carried out across multiple machines. It collects all information ([events](Eventos_en.md), [alerts](Alertas_en.md), [logs](Logs)) to keep organization personnel informed.

### Steps (summarized) performed by a SIEM
1. **Collection**: machines send their logs to the central server (the SIEM).
2. **Normalization**: data formats vary between systems, so they must be normalized.
3. **Correlation**: the system automatically correlates the data.
4. **Alerting**: the machine detects something suspicious and communicates it to human personnel.
