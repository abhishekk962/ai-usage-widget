# Detection methodology

## How the pattern was developed

The experiments live in the original `ai-network-activity` repository. Its October 19 boundary-detector commit (`9d72364`) references the original matcher, but the matcher source is absent from that commit. The implementation in [`detector.py`](detector.py) is a snapshot of the later reconstruction in `scripts/live_visual.py`. The saved rule settings, packet motifs, and subsequent live exports show how the rules evolved. They leave some of the original threshold choices undocumented.

1. **Capture labels and packets together.** `scripts/capture.py` starts Chrome through mitmdump and captures TCP and UDP traffic with Scapy. The proxy records ChatGPT's `/backend-api/f/conversation` HTTP flows. These give application-level request start and end times to compare with packet timing.
2. **Put both streams on a common timeline.** `scripts/save.py` imports paired captures into `data/network_activity.db`, decodes conversation messages, and records capture IDs, endpoints, timestamps, and lengths. It also calculates inter-arrival time against the preceding packet in the same direction. The matcher calculates elapsed time from the specific packets in a candidate sequence.
3. **Inspect the labeled traffic.** `queries/packets-for-specific-url-request.sql` aligns packets with HTTP requests by capture, bidirectional endpoint tuple, and time. `scripts/visualize.py` plots sent and received packet lengths alongside HTTP and decoded-message timestamps, with detected intervals overlaid. The saved motifs show two outgoing large–small pairs around the start and a three-packet incoming sequence around the end.
4. **Replay using packet metadata.** `scripts/detect.py` and `scripts/detect_request_boundaries.py` replay time-ordered TCP packets by capture and connection. The live dashboard in `scripts/live_visual.py` adds candidate markers and exports packet timelines, events, and rule settings. The widget applies the same start rules to its own live feed.

## How starts and ends are calculated

The live widget accepts TCP packets with exactly one known local endpoint and orients the connection as `(local IP, local port, remote IP, remote port)`. It uses the captured packet length from Scapy's `len(packet)`, including the headers visible to the capture interface. These sizes can reflect packet coalescing and offload behavior. The matcher discards packets of 80 bytes or less before looking for markers.

For a start, consider four outgoing packets A, B, C, and D on the same connection. A and B must be adjacent in the outgoing stream after the size filter, as must C and D. Incoming packets and packets excluded by the size filter do not break adjacency. Other outgoing packets may appear between the pairs.

| Packet | Captured bytes | Timing |
| --- | ---: | --- |
| A | 16,000–30,000 | Timestamp recorded for the start |
| B | 81–11,999 | At most 80 ms after A |
| C | 12,000–18,000 | Strictly later than A, and at or after B |
| D | 81–11,999 | At most 80 ms after C and at most 800 ms after A |

When C and D match, the matcher chooses the oldest qualifying A–B pair. A must be at least one second after the previous recorded start on that connection. The widget inserts a row as soon as it receives this start event.

The detector can also pair a start with an end. It looks for three incoming markers in order within two seconds. Marker 1 accepts 386–388, 441–442, 490–494, 508–516, or 657–659 bytes. Marker 2 accepts 98–102 bytes and marker 3 accepts 84–86 bytes. The ranges are inclusive. Sizes outside the marker bands can appear between them. The third marker supplies the end timestamp. A new start supersedes an unfinished interval on the same connection, and an interval times out after 600 seconds. The widget's count depends only on the start event, so missed ends and timeouts leave the count intact.

## What the saved evidence says about the thresholds

The table summarizes the 30 saved `packet_pattern_v1` boundaries from two captures. Sizes come from the saved motif JSON. Pair gaps are calculated from the relative timestamps of the two packets in each pair. These rows were already selected by a detector, so they show what the historical rules captured.

| Feature | Observed in the 30 saved motifs | Interpretation |
| --- | ---: | --- |
| A size | 18,804–22,741 B | Saved settings used 18,000–30,000 B. The band brackets the observed cluster. |
| B size | 1,045–4,147 B | The original small-packet bounds were unavailable. The reconstruction uses the space above the 80 B cutoff and below the 12,000 B lower bound for C. |
| C size | 13,676–15,666 B | The saved and live rules use 12,000–18,000 B, a band around the observed cluster. |
| D size | 290–975 B | The same reconstructed small-packet band covers this smaller group. |
| A to B / C to D | 0.6–29.2 ms / 1.5–27.0 ms | The saved 80 ms cutoff leaves room beyond both observed pair gaps. |
| A to D | 35.8–462.4 ms | The saved 800 ms cutoff allows a longer gap between the two pairs. |
| End sizes | 386, 99, and 85 B in every row | Later live rules add nearby sizes and additional first-marker bands. |
| First to third end marker | 15.9–748.5 ms | The saved two-second cutoff leaves room beyond the observed span. |

- **Why 16,000 B replaced 18,000 B.** The November 9 session exported at 15:01 UTC still used 18,000 B. The 15:22 and 15:36 UTC exports used 16,000 B and each recorded a start beginning with a 16,460 B packet. One was `16,460 → 4,106 → 12,754 → 824` B, spanning 308.9 ms. The 15:48 UTC export recorded starts at 16,854, 16,460, and 16,467 B. Lowering the floor retains these sequences. Replaying the original database with the old floor and all other current rules gives 33 starts. The current floor gives 34, with 30 completed boundaries in both replays.
- **How the end sizes broadened.** The 15:22 UTC export used exact first-marker sizes 386, 490, and 510 B. The 15:36 UTC export added 514 B. The 15:48 UTC export used several bands and contains a same-connection `442 → 101 → 85` B sequence within about 9 ms. The current rule also accepts 441–442 B. The exports include a `440 → 101 → 85` B sequence as well, so those examples alone cannot establish that 441 B is the best lower bound. The raw session exports have no corresponding HTTP labels for these sequences.
- **Operational cutoffs.** The saved settings include the 80 B size filter, one-second debounce, and 600-second timeout. The size filter keeps very small packets out of the sequence, the debounce limits repeated starts, and the timeout bounds unfinished intervals. The available records do not show a parameter sweep or how those particular values were chosen.

## Reproduce the checks

From the original research checkout, with the local reference database available:

```powershell
python scripts/detect.py --dry-run
python -m unittest discover -s scripts -p test_detect_request_boundaries.py -v
python scripts/visualize.py
```

The dry run scanned 187,585 packet records across 3,388 TCP connections, found 34 starts and 31 ends, and paired 30 boundaries. The database test compares the 30 reproduced boundaries and their exact packet IDs against the saved results. This checks compatibility with the reference dataset. The unpaired motifs have no independent classification in that check, and the widget counts unpaired starts. Live capture can vary with the browser, proxy, network adapter, and protocol. UDP traffic, including QUIC, does not enter the matcher.

Two adjacent experiments used the same research database:

- `scripts/predict_first_message.py` analyzes the first 250 ms after an already detected start. It compared first and later conversation messages across 30 matched requests and fit a 46,488 B outgoing-volume split. That threshold classifies message order within the detected set. The widget counts every qualifying start using the four-packet rule above.
- `scripts/analyze_token_timing.py` uses decoded message timestamps and token estimates from `queries/token-usage-by-http-request.sql` to compare token volume, response latency, and request lifespan. These are application-level measurements. The widget uses packet sizes and times only.
