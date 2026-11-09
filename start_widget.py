"""Floating history of AI Usage detections.

    python -m pip install -r requirements.txt
    python start_widget.py --iface "Wi-Fi"  # Administrator on Windows
    python start_widget.py --demo           # Sample activity in memory

Click the circle to open history. Drag to move it, or right-click to quit.
Use the month arrows to browse history and click a date for its message chart.
Detections go to data/start_widget.sqlite3 by default. Matching covers all
remote IPv4 and IPv6 addresses and TCP ports on the selected interface.
The UI uses Qt Widgets through PySide6 Essentials. Live capture uses Scapy
with Npcap on Windows.
"""

import argparse
from calendar import monthrange
from collections import Counter
from contextlib import closing
from datetime import date, datetime, time as wall_time, timedelta
from math import ceil
from pathlib import Path
from queue import Empty, Full, Queue, SimpleQueue
import random
import sqlite3
from threading import Event, Thread
import time

try:
    from PySide6.QtCore import QEasingCurve, QPointF, QRectF, Qt, QTimer, QVariantAnimation, Signal
    from PySide6.QtGui import (
        QColor, QFont, QGuiApplication, QKeySequence, QLinearGradient, QPainter, QPainterPath, QPen,
        QPolygonF, QShortcut,
    )
    from PySide6.QtWidgets import (
        QAbstractButton, QApplication, QHBoxLayout, QLabel, QMenu, QMessageBox, QPushButton,
        QVBoxLayout, QWidget,
    )
except ModuleNotFoundError as error:
    if error.name != 'PySide6':
        raise
    raise SystemExit('Install the widget UI with: python -m pip install PySide6-Essentials') from None

from detector import Packet, PatternMatcher, connection_key, discover_local_ips


DEFAULT_HISTORY = Path(__file__).resolve().parent / 'data' / 'start_widget.sqlite3'
APP_TITLE = 'AI Usage'
INTERVAL_MINUTES = 15
INTERVALS_PER_DAY = 24 * 60 // INTERVAL_MINUTES
ORB = 52
BG, SURFACE, BORDER = '#0d0d0d', '#141414', '#2b2b2b'
TEXT, MUTED = '#fafafa', '#a3a3a3'
HEAT = ('#252525', '#545454', '#858585', '#b9b9b9', '#fafafa')
FONT_FAMILIES = ('Inter', 'Segoe UI', 'sans-serif')
FLOATING = Qt.WindowType.Tool | Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint


class History:
    """Store the motif's first packet time and use local time in the UI."""

    def __init__(self, db):
        self.db = db
        self.db.execute('''CREATE TABLE IF NOT EXISTS starts (
            started_at REAL NOT NULL,
            local_ip TEXT NOT NULL,
            local_port INTEGER NOT NULL,
            remote_ip TEXT NOT NULL,
            remote_port INTEGER NOT NULL,
            PRIMARY KEY (started_at, local_ip, local_port, remote_ip, remote_port)
        )''')

    def record(self, event):
        # Completion, end and timeout events must not create another row.
        if event['kind'] == 'start':
            with self.db:
                self.db.execute('INSERT INTO starts VALUES (?, ?, ?, ?, ?) ON CONFLICT DO NOTHING',
                                (event['start'], *event['flow']))

    def counts_in_month(self, month):
        rows = self.db.execute('SELECT started_at FROM starts WHERE started_at >= ? AND started_at < ?',
                               (midnight(month), midnight(next_month(month))))
        return Counter(datetime.fromtimestamp(timestamp).date() for timestamp, in rows)

    def count_on(self, day):
        return self.db.execute('SELECT count(*) FROM starts WHERE started_at >= ? AND started_at < ?',
                               (midnight(day), midnight(day + timedelta(days=1)))).fetchone()[0]

    def message_frequency(self, day):
        rows = self.db.execute('SELECT started_at FROM starts WHERE started_at >= ? AND started_at < ?',
                               (midnight(day), midnight(day + timedelta(days=1))))
        counts = [0] * INTERVALS_PER_DAY
        for timestamp, in rows:
            # Repeated local intervals at the end of daylight saving share a bin.
            counts[interval_index(datetime.fromtimestamp(timestamp))] += 1
        return tuple(counts)


def midnight(day):
    # Calculate each boundary separately so 23- and 25-hour days work too.
    return datetime.combine(day, wall_time.min).timestamp()


def next_month(month):
    return month + timedelta(days=monthrange(month.year, month.month)[1])


def interval_index(clock):
    return (clock.hour * 60 + clock.minute) // INTERVAL_MINUTES


def capture(args, stop, status):
    """Run capture off the GUI thread and hand only oriented TCP packets to the matcher."""
    try:
        from scapy.all import AsyncSniffer, IP, IPv6, TCP, conf

        local_ips = discover_local_ips(args.local_ip)
        if not local_ips:
            raise ValueError('No local addresses found. Pass --local-ip YOUR_IP.')
        interface = str(args.iface or conf.iface)
        packets = Queue(maxsize=50_000)
        ready = Event()
        dropped = 0

        def enqueue(packet):
            nonlocal dropped
            tcp = packet.getlayer(TCP)
            ip = packet.getlayer(IP) or packet.getlayer(IPv6)
            if tcp is None or ip is None:
                return
            connection = connection_key(ip.src, tcp.sport, ip.dst, tcp.dport, local_ips)
            if connection is None:
                return
            key, outgoing = connection
            try:
                packets.put_nowait((key, Packet(float(packet.time), len(packet), outgoing)))
            except Full:
                dropped += 1

        with closing(sqlite3.connect(args.history)) as db:
            matcher = PatternMatcher(on_event=History(db).record)
            sniffer = AsyncSniffer(iface=args.iface, prn=enqueue, store=False,
                                   started_callback=ready.set)
            sniffer.start()

            def match(key, packet):
                state = matcher.flows.get(key)
                if state is None or packet.time >= state.last_seen:
                    matcher.feed(key, packet)

            last_update = 0
            try:
                # If quit was requested during startup, wait until Scapy opens the
                # socket (or reports an error) before attempting to close it.
                while not (stop.is_set() and ready.is_set()):
                    if not sniffer.thread.is_alive():
                        break
                    try:
                        match(*packets.get(timeout=.15))
                    except Empty:
                        pass
                    if ready.is_set() and time.monotonic() - last_update >= 1:
                        last_update = time.monotonic()
                        if packets.empty():
                            matcher.expire(time.time())
                        detail = f'All remote IPv4/IPv6 · {interface}'
                        if dropped:
                            detail += f' · {dropped:,} dropped packets'
                        status.put(('Live' if not dropped else 'Packet drops', detail))
            finally:
                if ready.is_set() and sniffer.thread.is_alive():
                    sniffer.stop()

            # Capture is stopped. Persist any starts in the remaining packets.
            while not packets.empty():
                match(*packets.get_nowait())
            sniffer.join()  # Re-raise startup and socket errors after draining.
            if not stop.is_set():
                raise RuntimeError('Packet capture stopped unexpectedly.')
    except ImportError:
        status.put(('Capture error', 'Install Scapy in this Python environment to capture live traffic.'))
    except sqlite3.Error as error:
        status.put(('History error', str(error)))
    except Exception as error:
        status.put(('Capture error', f'{error} Check the interface, Npcap and capture privileges.'))


def seed_demo(history, today):
    """Replay clusters of synthetic messages through the real matcher."""
    rng = random.Random(32)
    matcher = PatternMatcher(on_event=history.record)
    remotes = ('203.0.113.8', '198.51.100.22', '2001:db8::3')
    for days_ago in reversed(range(182)):
        day = today - timedelta(days=days_ago)
        first = midnight(day)
        end = time.time() if day == today else midnight(day + timedelta(days=1))
        minutes = (end - first) / 60
        if day == today:
            # Give the demo a few bursts before the current time, even early in the day.
            count = max(18, min(150, round(minutes / 5)))
            centers = (minutes * .39, minutes * .64, minutes * .88)
            weights = (3, 5, 4)
            spread = min(25, minutes / 12)
        else:
            count = rng.choice((0, 0, 2, 5, 10, 22, 48, 76, 120))
            centers = tuple(hour * 60 + rng.randint(-30, 30) for hour in (9, 12.5, 16, 20))
            weights = (4, 2, 4, 2)
            spread = rng.randint(15, 42)
        offsets = sorted(rng.gauss(center, spread) for center in rng.choices(centers, weights, k=count))
        for index, offset in enumerate(offsets):
            start = first + offset * 60
            if not first <= start < end - .18:
                continue
            remote = remotes[index % len(remotes)]
            local = '2001:db8::10' if ':' in remote else '192.0.2.10'
            key = (local, 51000 + index, remote, 443)
            for offset, size in ((0, 16460), (.03, 4246), (.15, 12750), (.18, 920)):
                matcher.feed(key, Packet(start + offset, size, True))


STYLE = f"""
QWidget {{ color: {TEXT}; }}
QLabel#title {{ font-size: 17px; font-weight: 700; }}
QLabel#month {{ font-size: 13px; font-weight: 600; }}
QLabel#chartDate {{ font-size: 12px; font-weight: 600; }}
QLabel#chartTitle {{ color: {MUTED}; font-size: 11px; font-weight: 500; }}
QLabel#muted {{ color: {MUTED}; font-size: 11px; }}
QPushButton {{
    background: transparent; border: 1px solid transparent;
    border-radius: 6px; padding: 0;
}}
QPushButton:hover, QPushButton:focus {{ background: #242424; }}
QPushButton:pressed {{ background: #343434; }}
QMenu {{ background: {SURFACE}; border: 1px solid {BORDER}; padding: 4px; }}
QMenu::item {{ padding: 6px 18px; border-radius: 4px; }}
QMenu::item:selected {{ background: #303030; }}
QToolTip {{ background: #202020; color: {TEXT}; border: 1px solid #444; padding: 3px; }}
"""


def label(text, role=''):
    widget = QLabel(text)
    widget.setObjectName(role)
    return widget


def font(pixels, weight=QFont.Weight.Normal):
    result = QFont()
    result.setFamilies(FONT_FAMILIES)
    result.setPixelSize(pixels)
    result.setWeight(weight)
    return result


def message_count(count):
    unit = 'message' if count == 1 else 'messages'
    return f'{count:,} detected {unit}'


class Launcher(QAbstractButton):
    """Paint a high-DPI circle and distinguish clicks from drags."""

    moved = Signal()

    def __init__(self):
        super().__init__()
        self.setWindowFlags(FLOATING)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setFixedSize(ORB, ORB)
        self.setWindowTitle(APP_TITLE)
        self.setAccessibleName(f'Open {APP_TITLE}')
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.face = QRectF(2, 2, ORB - 4, ORB - 4)
        self.count = 0
        self.state = 'Starting'
        self.press = None
        self.dragging = False
        self.hover = QVariantAnimation(self, duration=130, startValue=0.0, endValue=1.0)
        self.hover.valueChanged.connect(lambda _value: self.update())

    def hitButton(self, point):
        center = self.face.center()
        radius = self.face.width() / 2
        return (point.x() - center.x()) ** 2 + (point.y() - center.y()) ** 2 <= radius ** 2

    def set_activity(self, count, state):
        if (count, state) != (self.count, self.state):
            self.count, self.state = count, state
            self.setAccessibleDescription(f'{message_count(count)} today. {state}.')
            self.update()

    def enterEvent(self, event):
        self.hover.setDirection(QVariantAnimation.Direction.Forward)
        self.hover.start()
        super().enterEvent(event)

    def leaveEvent(self, event):
        self.hover.setDirection(QVariantAnimation.Direction.Backward)
        self.hover.start()
        super().leaveEvent(event)

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        strength = self.hover.currentValue()
        shade = 26 + round(strength * 15)
        gradient = QLinearGradient(self.face.topLeft(), self.face.bottomLeft())
        gradient.setColorAt(0, QColor(shade, shade, shade))
        gradient.setColorAt(1, QColor(BG))
        edge = 68 + round(strength * 51)
        painter.setPen(QPen(QColor(edge, edge, edge), 1.2))
        painter.setBrush(gradient)
        painter.drawEllipse(self.face)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(TEXT if self.state in ('Live', 'Demo') else MUTED))
        painter.drawEllipse(QRectF(ORB / 2 - 2, 10, 4, 4))
        painter.setPen(QColor(TEXT))
        painter.setFont(font(20 if self.count < 1000 else 14, QFont.Weight.DemiBold))
        painter.drawText(QRectF(0, 15, ORB, 26), Qt.AlignmentFlag.AlignCenter,
                         str(self.count) if self.count < 1000 else '999+')

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton and self.hitButton(event.position()):
            self.press = event.globalPosition().toPoint() - self.pos()
            self.dragging = False
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        if self.press is not None:
            target = event.globalPosition().toPoint() - self.press
            if self.dragging or (target - self.pos()).manhattanLength() >= QApplication.startDragDistance():
                self.dragging = True
                self.setDown(False)
                self.move(target)
                self.moved.emit()
                return
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.press = None
            if self.dragging:
                self.dragging = False
                self.setDown(False)
                event.accept()
                return
        super().mouseReleaseEvent(event)

    def closeEvent(self, event):
        QApplication.exit(0)
        super().closeEvent(event)


class Calendar(QWidget):
    """Render one Monday-first month, shaded by detected messages per day."""

    day_selected = Signal(object)
    GRID_TOP = 19
    CELL_GAP = 5
    SIDE_PAD = 2  # Space for the selected cell's outer ring.

    def __init__(self, width):
        super().__init__()
        self.cell_size = (width - 2 * self.SIDE_PAD - 6 * self.CELL_GAP) / 7
        self.pitch = self.cell_size + self.CELL_GAP
        self.setFixedSize(width, ceil(self.GRID_TOP + 6 * self.pitch - self.CELL_GAP + self.SIDE_PAD))
        self.setMouseTracking(True)
        self.setAccessibleName('Monthly activity')
        self.today = self.selected = date.today()
        self.month = self.today.replace(day=1)
        self.counts = Counter()
        self.hovered = None

    def set_month(self, today, selected, counts):
        month = selected.replace(day=1)
        if month != self.month:
            self.set_hover(None)
        self.today, self.selected, self.month, self.counts = today, selected, month, counts
        self.update()

    def cell(self, row, column):
        return QRectF(self.SIDE_PAD + column * self.pitch, self.GRID_TOP + row * self.pitch,
                      self.cell_size, self.cell_size)

    def day_at(self, point):
        column = int((point.x() - self.SIDE_PAD) // self.pitch)
        row = int((point.y() - self.GRID_TOP) // self.pitch)
        if 0 <= column < 7 and 0 <= row < 6 and self.cell(row, column).contains(point):
            number = 1 + row * 7 + column - self.month.weekday()
            if 1 <= number <= monthrange(self.month.year, self.month.month)[1]:
                day = self.month.replace(day=number)
                if day <= self.today:
                    return day
        return None

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setFont(font(10, QFont.Weight.Medium))
        painter.setPen(QColor(MUTED))
        for column, caption in enumerate(('Mo', 'Tu', 'We', 'Th', 'Fr', 'Sa', 'Su')):
            cell = self.cell(0, column)
            painter.drawText(QRectF(cell.x(), 0, cell.width(), 16),
                             Qt.AlignmentFlag.AlignCenter, caption)

        painter.setFont(font(11, QFont.Weight.DemiBold))
        shades = tuple(QColor(color) for color in HEAT)
        for number in range(1, monthrange(self.month.year, self.month.month)[1] + 1):
            day = self.month.replace(day=number)
            row, column = divmod(self.month.weekday() + number - 1, 7)
            cell = self.cell(row, column)
            count = self.counts[day]
            level = sum(count >= threshold for threshold in (1, 3, 6, 10))
            if day > self.today:
                fill, text = QColor('#171717'), QColor('#757575')
            else:
                fill, text = shades[level], QColor(BG if level >= 2 else TEXT)
            if day == self.selected:
                painter.setBrush(Qt.BrushStyle.NoBrush)
                painter.setPen(QPen(QColor(TEXT), 1))
                painter.drawRoundedRect(cell.adjusted(-1.5, -1.5, 1.5, 1.5), 4.5, 4.5)
            painter.setBrush(fill)
            painter.setPen(QPen(QColor('#909090'), 1.2)
                           if day == self.hovered and day != self.selected else Qt.PenStyle.NoPen)
            painter.drawRoundedRect(cell, 3, 3)
            painter.setPen(text)
            painter.drawText(cell, Qt.AlignmentFlag.AlignCenter, str(number))

    def mouseMoveEvent(self, event):
        self.set_hover(self.day_at(event.position()))

    def leaveEvent(self, _event):
        self.set_hover(None)

    def set_hover(self, day):
        if day == self.hovered:
            return
        self.hovered = day
        self.setCursor(Qt.CursorShape.PointingHandCursor if day else Qt.CursorShape.ArrowCursor)
        if day is None:
            self.setToolTip('')
        else:
            self.setToolTip(message_count(self.counts[day]))
        self.update()

    def mousePressEvent(self, event):
        day = self.day_at(event.position())
        if day is not None and event.button() == Qt.MouseButton.LeftButton:
            self.day_selected.emit(day)


class IconButton(QPushButton):
    """Draw centered strokes independently of the font's glyph metrics."""

    def __init__(self, name, direction=0):
        super().__init__()
        self.direction = direction
        self.setAccessibleName(name)
        self.setToolTip(name)
        self.setFixedSize(24, 24)

    def paintEvent(self, event):
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.translate(QRectF(self.rect()).center())
        color = TEXT if self.underMouse() else MUTED
        painter.setPen(QPen(QColor(color if self.isEnabled() else '#4b4b4b'), 1.5,
                            Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
        if self.direction:
            tip = 2.5 * self.direction
            painter.drawPolyline(QPolygonF([QPointF(-tip, -4), QPointF(tip, 0), QPointF(-tip, 4)]))
        else:
            painter.drawLine(QPointF(-3.5, -3.5), QPointF(3.5, 3.5))
            painter.drawLine(QPointF(3.5, -3.5), QPointF(-3.5, 3.5))


def smooth_frequency(counts):
    """Use a five-bin weighted average and renormalize at the edges."""
    smoothed = []
    for index in range(len(counts)):
        neighbors = range(max(0, index - 2), min(len(counts), index + 3))
        weights = [3 - abs(index - neighbor) for neighbor in neighbors]
        total = sum(counts[neighbor] * weight for neighbor, weight in zip(neighbors, weights))
        smoothed.append(total / sum(weights))
    return tuple(smoothed)


def clock_label(minutes):
    hour, minute = divmod(minutes % (24 * 60), 60)
    return f'{hour % 12 or 12}:{minute:02} {"AM" if hour < 12 else "PM"}'


def trend_path(points):
    """Join evenly spaced samples with continuous slopes and no overshoot."""
    path = QPainterPath(points[0])
    changes = [right.y() - left.y() for left, right in zip(points, points[1:])]
    if not changes:
        return path
    # Flatten at turning points. Elsewhere the harmonic mean damps steep changes.
    slopes = [changes[0]]
    for left, right in zip(changes, changes[1:]):
        slopes.append(2 * left * right / (left + right) if left * right > 0 else 0)
    slopes.append(changes[-1])
    for index, (left, right) in enumerate(zip(points, points[1:])):
        third = (right.x() - left.x()) / 3
        path.cubicTo(left.x() + third, left.y() + slopes[index] / 3,
                     right.x() - third, right.y() - slopes[index + 1] / 3,
                     right.x(), right.y())
    return path


class UsageChart(QWidget):
    """Plot a smoothed 15-minute series and show raw counts on hover."""

    def __init__(self):
        super().__init__()
        self.setFixedHeight(112)
        self.setMouseTracking(True)
        self.setAccessibleName('Detected AI messages per 15 minutes')
        self.setAccessibleDescription(message_count(0))
        self.counts = (0,) * INTERVALS_PER_DAY
        self.values = self.counts
        self.hovered = None

    def set_usage(self, counts):
        if counts == self.counts:
            return
        self.counts = counts
        self.values = smooth_frequency(counts)
        self.setAccessibleDescription(message_count(sum(counts)))
        self.set_hover(self.hovered)

    def plot(self):
        return QRectF(7, 9, self.width() - 14, self.height() - 33)

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.setRenderHints(QPainter.RenderHint.Antialiasing | QPainter.RenderHint.TextAntialiasing)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.setPen(QPen(QColor(BORDER), 1))
        painter.drawRoundedRect(QRectF(self.rect()).adjusted(.5, .5, -.5, -.5), 8, 8)

        plot = self.plot()
        step = plot.width() / INTERVALS_PER_DAY
        high = max(self.values)
        peak = max(1, ceil(high))
        painter.setPen(QColor(MUTED))
        painter.setFont(font(10))
        metrics = painter.fontMetrics()
        for hour, caption in ((0, '12 AM'), (6, '6 AM'), (12, '12 PM'), (18, '6 PM')):
            x = plot.left() + hour / 24 * plot.width()
            width = metrics.horizontalAdvance(caption) + 2
            left = max(plot.left(), min(x - width / 2, plot.right() - width))
            painter.drawText(QRectF(left, plot.bottom() + 5, width, 14),
                             Qt.AlignmentFlag.AlignCenter, caption)

        points = [QPointF(plot.left() + (index + .5) * step, plot.bottom() - value / peak * plot.height())
                  for index, value in enumerate(self.values)]
        if self.hovered is not None:
            x = points[self.hovered].x()
            painter.setPen(QPen(QColor('#4b4b4b'), 1))
            painter.drawLine(QPointF(x, plot.top()), QPointF(x, plot.bottom()))
        painter.setPen(QPen(QColor(TEXT if high else MUTED), 1.85,
                            Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
        painter.drawPath(trend_path(points))
        if self.hovered is not None or len(points) == 1:
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(TEXT))
            painter.drawEllipse(points[self.hovered or 0], 2.75, 2.75)

    def mouseMoveEvent(self, event):
        plot = self.plot()
        position = event.position()
        index = int((position.x() - plot.left()) * INTERVALS_PER_DAY / plot.width())
        hovered = index if plot.contains(position) and 0 <= index < len(self.counts) else None
        if hovered != self.hovered:
            self.set_hover(hovered)

    def leaveEvent(self, _event):
        self.set_hover(None)

    def set_hover(self, index):
        self.hovered = index if index is not None and index < len(self.counts) else None
        if self.hovered is None:
            self.setToolTip('')
        else:
            minutes = self.hovered * INTERVAL_MINUTES
            interval = f'{clock_label(minutes)} – {clock_label(minutes + INTERVAL_MINUTES)}'
            self.setToolTip(f'{interval}  ·  {message_count(self.counts[self.hovered])}')
        self.update()


class HistoryPanel(QWidget):
    """A compact month picker and AI message chart."""

    dismissed = Signal()
    month_changed = Signal(int)

    def __init__(self):
        super().__init__(None, FLOATING)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setWindowTitle(APP_TITLE)
        panel_width, side_margin = 266, 9
        self.setFixedWidth(panel_width)
        self.setFont(font(13))
        self.setStyleSheet(STYLE)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(side_margin, 10, side_margin, 10)
        layout.setSpacing(6)

        header = QHBoxLayout()
        header.addWidget(label(APP_TITLE, 'title'))
        header.addStretch()
        close = IconButton('Close history')
        close.clicked.connect(self.dismissed)
        header.addWidget(close)
        layout.addLayout(header)
        self.escape = QShortcut(QKeySequence('Escape'), self)
        self.escape.activated.connect(self.dismissed)

        month_row = QHBoxLayout()
        month_row.setSpacing(2)
        self.month_heading = label('', 'month')
        month_row.addWidget(self.month_heading)
        month_row.addStretch()
        previous = IconButton('Previous month', -1)
        previous.clicked.connect(lambda: self.month_changed.emit(-1))
        month_row.addWidget(previous)
        self.next_button = IconButton('Next month', 1)
        self.next_button.clicked.connect(lambda: self.month_changed.emit(1))
        month_row.addWidget(self.next_button)
        layout.addLayout(month_row)

        self.warning = label('', 'muted')
        self.warning.hide()
        layout.addWidget(self.warning)
        self.calendar = Calendar(panel_width - 2 * side_margin)
        layout.addWidget(self.calendar, alignment=Qt.AlignmentFlag.AlignHCenter)
        detail = QHBoxLayout()
        self.day_heading = label('', 'chartDate')
        detail.addWidget(self.day_heading)
        detail.addStretch()
        metric = label('Messages Sent', 'chartTitle')
        metric.setToolTip('The line smooths the 15-minute counts. Hover for exact counts.')
        detail.addWidget(metric)
        layout.addLayout(detail)
        self.chart = UsageChart()
        layout.addWidget(self.chart)

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(QPen(QColor(BORDER), 1))
        painter.setBrush(QColor(BG))
        painter.drawRoundedRect(QRectF(self.rect()).adjusted(.5, .5, -.5, -.5), 13, 13)

    def closeEvent(self, event):
        event.ignore()
        self.dismissed.emit()



class StartWidget:
    """Keep storage polling, date selection and the two floating windows in sync."""

    def __init__(self, history, status, demo):
        self.history, self.status = history, status
        self.today = self.selected = date.today()
        self.current_interval = interval_index(datetime.now())
        self.today_count = 0
        self.data_version = None
        self.state, self.detail = ('Demo', 'Synthetic sample activity') if demo else (
            'Starting', 'Opening the capture interface…')

        self.launcher = Launcher()
        self.panel = HistoryPanel()
        self.panel_open = False
        self.progress = 0.0
        self.animation = QVariantAnimation(self.panel, duration=170)
        self.animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        self.animation.valueChanged.connect(self.animate_panel)
        self.animation.finished.connect(self.finish_animation)
        self.launcher.clicked.connect(self.toggle)
        self.launcher.moved.connect(self.position_panel)
        self.launcher.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.launcher.customContextMenuRequested.connect(self.open_menu)
        self.panel.dismissed.connect(self.dismiss)
        self.panel.month_changed.connect(self.change_month)
        self.panel.calendar.day_selected.connect(self.select_day)

        screen = QApplication.primaryScreen().availableGeometry()
        self.launcher.move(screen.x() + screen.width() - ORB - 24,
                           screen.y() + screen.height() - ORB - 24)
        self.refresh()
        self.launcher.show()
        self.timer = QTimer(self.launcher, interval=750)
        self.timer.timeout.connect(self.refresh)
        self.timer.start()

    def change_month(self, direction):
        month = self.selected.replace(day=1)
        destination = (month - timedelta(days=1)).replace(day=1) if direction < 0 else next_month(month)
        current = self.today.replace(day=1)
        if destination <= current:
            self.select_day(self.today if destination == current else destination)

    def select_day(self, day):
        self.selected = day
        try:
            self.show_day()
        except sqlite3.Error as error:
            self.set_status('History error', str(error))

    def show_day(self):
        day = self.selected
        month = day.replace(day=1)
        counts = self.history.counts_in_month(month)
        frequency = self.history.message_frequency(day)
        self.panel.calendar.set_month(self.today, day, counts)
        self.panel.month_heading.setText(month.strftime('%B %Y'))
        self.panel.next_button.setEnabled(month < self.today.replace(day=1))
        self.panel.day_heading.setText('Today' if day == self.today else f'{day:%a, %b} {day.day}')
        visible = self.current_interval + 1 if day == self.today else INTERVALS_PER_DAY
        self.panel.chart.set_usage(frequency[:visible])

    def set_status(self, state, detail):
        warning = '' if state in ('Demo', 'Live', 'Starting') else state
        if self.panel.warning.text() != warning:
            self.panel.warning.setText(warning)
            self.panel.warning.setVisible(bool(warning))
            self.panel.adjustSize()
            self.position_panel()
        self.panel.warning.setToolTip(detail if warning else '')
        self.launcher.set_activity(self.today_count, state)
        tooltip = f'{message_count(self.today_count)} today\n{detail}'
        if self.launcher.toolTip() != tooltip:
            self.launcher.setToolTip(tooltip)

    def refresh(self):
        while not self.status.empty():
            self.state, self.detail = self.status.get_nowait()
        try:
            now = datetime.now()
            today = now.date()
            interval = interval_index(now)
            version = self.history.db.execute('PRAGMA data_version').fetchone()[0]
            if today != self.today or interval != self.current_interval or version != self.data_version:
                self.today_count = self.history.count_on(today)
                if self.selected == self.today or self.selected > today:
                    self.selected = today
                self.today = today
                self.current_interval = interval
                if self.panel_open:
                    self.show_day()
                self.data_version = version
            self.set_status(self.state, self.detail)
        except sqlite3.Error as error:
            self.set_status('History error', str(error))

    def open_menu(self, point):
        menu = QMenu(self.launcher)
        menu.setFont(font(12))
        menu.setStyleSheet(STYLE)
        menu.addAction(f'Toggle {APP_TITLE}', self.toggle)
        menu.addAction('Quit', lambda: QApplication.exit(0))
        menu.exec(self.launcher.mapToGlobal(point))

    def position_panel(self):
        if not self.panel.isVisible() and not self.panel_open:
            return
        orb = self.launcher.geometry()
        screen = QGuiApplication.screenAt(orb.center()) or self.launcher.screen()
        area = screen.availableGeometry()
        width, height = self.panel.width(), self.panel.height()
        left = min(orb.right() + 1 - width, area.right() + 1 - width)
        top = orb.top() - height - 10
        below = top < area.top()
        if below:
            top = orb.bottom() + 11
        offset = round((1 - self.progress) * (9 if not below else -9))
        self.panel.move(max(area.left(), left),
                        max(area.top(), min(top + offset, area.bottom() + 1 - height)))

    def animate_panel(self, value):
        self.progress = value
        self.panel.setWindowOpacity(value)
        self.position_panel()

    def finish_animation(self):
        if not self.panel_open:
            self.panel.hide()

    def toggle(self):
        if self.panel_open:
            self.dismiss()
        else:
            self.panel_open = True
            self.select_day(self.today)
            self.panel.adjustSize()
            self.animate_panel(self.progress)
            self.panel.show()
            self.panel.raise_()
            self.panel.activateWindow()
            self.transition(1.0)

    def dismiss(self):
        if self.panel_open:
            self.panel_open = False
            self.transition(0.0)

    def transition(self, target):
        # Start at the current opacity so rapid clicks reverse the motion smoothly.
        self.animation.stop()
        self.animation.blockSignals(True)
        self.animation.setCurrentTime(0)
        self.animation.setStartValue(self.progress)
        self.animation.setEndValue(target)
        self.animation.blockSignals(False)
        self.animation.start()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--iface', help='Capture interface. Defaults to the routing interface.')
    parser.add_argument('--local-ip', action='append', default=[], help='Override local address discovery. Repeat as needed.')
    parser.add_argument('--history', type=Path, default=DEFAULT_HISTORY, help='SQLite file for usage history.')
    parser.add_argument('--demo', action='store_true', help='Open with isolated, synthetic sample history.')
    args = parser.parse_args()
    app = QApplication([])
    app.setApplicationName(APP_TITLE)
    app.setStyle('Fusion')
    app.setQuitOnLastWindowClosed(False)
    stop, status = Event(), SimpleQueue()
    worker = None
    try:
        if not args.demo:
            args.history.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(':memory:' if args.demo else args.history, timeout=.15)) as db:
            if not args.demo:
                db.execute('PRAGMA journal_mode = WAL')
            history = History(db)
            if args.demo:
                seed_demo(history, date.today())
            widget = StartWidget(history, status, args.demo)
            if not args.demo:
                worker = Thread(target=capture, args=(args, stop, status), daemon=True)
                worker.start()
            try:
                app.exec()
            finally:
                widget.timer.stop()
    except (OSError, sqlite3.Error) as error:
        QMessageBox.critical(None, f'{APP_TITLE} · History error', str(error))
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        if worker:
            worker.join(timeout=5)


if __name__ == '__main__':
    main()
