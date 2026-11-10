"""The disclaimer, install summary and trust prompt dialogs."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QStyle,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from qbit_plugin_dl.gui.columns import DISCLAIMER


class DisclaimerDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Safety notice")
        self.setModal(True)
        self.resize(560, 360)
        self.setMinimumSize(480, 300)
        layout = QVBoxLayout(self)
        text = QTextEdit()
        text.setReadOnly(True)
        text.setPlainText(DISCLAIMER)
        text.setMinimumHeight(200)
        text.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        text.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        layout.addWidget(text)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Yes | QDialogButtonBox.StandardButton.No
        )
        buttons.button(QDialogButtonBox.StandardButton.Yes).setText("Accept")
        buttons.button(QDialogButtonBox.StandardButton.No).setText("Decline")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)


class InstallSummaryDialog(QDialog):
    """Bounded, scrollable install result dialog (avoids huge QMessageBox width)."""

    def __init__(
        self,
        title: str,
        body: str,
        icon_kind: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        self.resize(560, 420)
        self.setMinimumSize(420, 280)
        self.setMaximumWidth(640)

        layout = QVBoxLayout(self)
        header = QHBoxLayout()
        icon_label = QLabel()
        icon_label.setPixmap(self._icon_for_kind(icon_kind).pixmap(32, 32))
        header.addWidget(icon_label)
        title_label = QLabel(title)
        title_label.setWordWrap(True)
        title_font = title_label.font()
        title_font.setBold(True)
        title_label.setFont(title_font)
        header.addWidget(title_label, stretch=1)
        layout.addLayout(header)

        text = QTextEdit()
        text.setReadOnly(True)
        text.setPlainText(body)
        text.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        text.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        text.setMinimumHeight(220)
        layout.addWidget(text, stretch=1)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)

    def _icon_for_kind(self, icon_kind: str) -> QIcon:
        style = self.style()
        if icon_kind == "critical":
            sp = QStyle.StandardPixmap.SP_MessageBoxCritical
        elif icon_kind == "warning":
            sp = QStyle.StandardPixmap.SP_MessageBoxWarning
        else:
            sp = QStyle.StandardPixmap.SP_MessageBoxInformation
        return style.standardIcon(sp)


class TrustPromptDialog(QDialog):
    """
    Bounded Trust once / Always trust / Cancel prompt with a scrollable list.

    A QMessageBox grows with its text, so a first-run category resolve listing
    dozens of sources filled the screen. Everything is plain text: labels and
    URLs come from the catalog.
    """

    ONCE = "once"
    ALWAYS = "always"

    def __init__(
        self,
        title: str,
        text: str,
        question: str,
        entries: list[str],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        self.resize(600, 440)
        self.setMinimumSize(440, 300)
        self.setMaximumWidth(720)
        self.choice: str | None = None

        layout = QVBoxLayout(self)
        header = QHBoxLayout()
        icon_label = QLabel()
        icon_label.setPixmap(
            self.style()
            .standardIcon(QStyle.StandardPixmap.SP_MessageBoxWarning)
            .pixmap(32, 32)
        )
        header.addWidget(icon_label, alignment=Qt.AlignmentFlag.AlignTop)
        self.text_label = QLabel(text)
        self.text_label.setTextFormat(Qt.TextFormat.PlainText)
        self.text_label.setWordWrap(True)
        header.addWidget(self.text_label, stretch=1)
        layout.addLayout(header)

        count = len(entries)
        self.question_label = QLabel(
            f"{question} ({count} source{'s' if count != 1 else ''})"
        )
        self.question_label.setTextFormat(Qt.TextFormat.PlainText)
        self.question_label.setWordWrap(True)
        layout.addWidget(self.question_label)

        self.entries_view = QTextEdit()
        self.entries_view.setReadOnly(True)
        self.entries_view.setPlainText("\n\n".join(entries))
        self.entries_view.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        self.entries_view.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )
        self.entries_view.setMinimumHeight(140)
        layout.addWidget(self.entries_view, stretch=1)

        buttons = QDialogButtonBox()
        self.always_btn = buttons.addButton(
            "Always trust", QDialogButtonBox.ButtonRole.YesRole
        )
        self.once_btn = buttons.addButton(
            "Trust once", QDialogButtonBox.ButtonRole.AcceptRole
        )
        self.cancel_btn = buttons.addButton(QDialogButtonBox.StandardButton.Cancel)
        # Enter / Escape must never approve an untrusted source.
        for btn in (self.always_btn, self.once_btn):
            btn.setAutoDefault(False)
            btn.setDefault(False)
        self.cancel_btn.setDefault(True)
        self.cancel_btn.setFocus()
        self.once_btn.clicked.connect(lambda: self._finish(self.ONCE))
        self.always_btn.clicked.connect(lambda: self._finish(self.ALWAYS))
        self.cancel_btn.clicked.connect(self.reject)
        layout.addWidget(buttons)

    def _finish(self, choice: str) -> None:
        self.choice = choice
        self.accept()


def show_plain_message(
    parent: QWidget | None,
    icon: QMessageBox.Icon,
    title: str,
    text: str,
    *,
    buttons: QMessageBox.StandardButton = QMessageBox.StandardButton.Ok,
    default: QMessageBox.StandardButton | None = None,
) -> QMessageBox.StandardButton:
    """
    Modal message box that never interprets *text* as HTML.

    The static ``QMessageBox.warning()``/``critical()`` helpers auto-detect rich
    text and open links, and their text here often includes catalog-controlled
    plugin names, URLs or error strings.
    """
    box = QMessageBox(icon, title, text, buttons, parent)
    box.setTextFormat(Qt.TextFormat.PlainText)
    if default is not None:
        box.setDefaultButton(default)
    box.exec()
    clicked = box.clickedButton()
    if clicked is None:
        return QMessageBox.StandardButton.NoButton
    return box.standardButton(clicked)
