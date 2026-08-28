"""Native, local-only desktop application for Wiki Memory.

The window is intentionally a thin façade over :mod:`wiki_spike.operational`.
It starts no server, opens no network connection, and adds no model or connector.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, simpledialog, ttk
except ImportError:  # Headless/support Python may not include the native Tk extension.
    tk = None  # type: ignore[assignment]
    filedialog = messagebox = simpledialog = ttk = None  # type: ignore[assignment]

from .desktop_service import (
    APP_NAME,
    DEFAULT_BACKUP_ROOT,
    DEFAULT_DATA_ROOT,
    DesktopMemoryService,
)
from .agent import ReadOnlyMemoryTools
from .store import LocalMemoryError, MemoryHit

WINDOW_TITLE = "Wiki Memory — 내 Mac의 암호화 메모"


def friendly_error(exc: BaseException) -> str:
    """Translate operator-facing storage failures into actionable Korean."""
    text = str(exc)
    lowered = text.casefold()
    if "authentication failed" in lowered:
        return "백업 암호가 다르거나 백업 파일이 손상되었습니다."
    if "permissions" in lowered or "0700" in lowered or "0600" in lowered:
        return "데이터 폴더의 보호 권한이 올바르지 않습니다. ‘상태 확인’에서 자동 복구를 실행하세요."
    if "integrity check failed" in lowered or "digest mismatch" in lowered:
        return "저장 데이터의 무결성 검사가 실패했습니다. 최근 백업으로 복구하세요."
    if "not initialized" in lowered or "incomplete" in lowered:
        return "메모 저장소가 완성되지 않았습니다. 앱을 다시 열어 자동 복구를 시도하세요."
    if "source must be utf-8" in lowered:
        return "UTF-8 텍스트 또는 Markdown 파일만 추가할 수 있습니다."
    if "exceeds" in lowered:
        return "파일이나 메모가 지원 크기를 초과했습니다. 더 작은 문서로 나누어 주세요."
    if "empty" in lowered:
        return "제목과 메모 내용을 입력해 주세요."
    if "title" in lowered or "label" in lowered:
        return "1~255자의 제목을 입력해 주세요."
    return text or "알 수 없는 오류가 발생했습니다."


def check_environment(root: str | Path, *, initialize: bool = True) -> dict[str, Any]:
    """Headless installation check used by packaging and support diagnostics."""
    target = Path(root).expanduser()
    if initialize:
        opened = DesktopMemoryService.open_or_initialize(target)
        service = opened.service
        first_run = opened.first_run
    else:
        service = DesktopMemoryService(target)
        first_run = False
    status = service.status()
    return {
        "app": APP_NAME,
        "desktop_toolkit": f"Tk {tk.TkVersion}" if tk is not None else "unavailable",
        "first_run": first_run,
        "root": str(target),
        "state": status["state"],
        "operational_ready": status["operational_ready"],
        "active_memories": status["active_memories"],
        "authority": status["authority"],
        "parallel_memory_database": status["parallel_memory_database"],
        "network_enabled": False,
        "external_models_enabled": False,
    }


class WikiMemoryApp:
    """One-window browse, edit, search, backup, and restore experience."""

    def __init__(
        self,
        window: tk.Tk,
        service: DesktopMemoryService,
        *,
        first_run: bool,
    ) -> None:
        self.window = window
        self.service = service
        self.first_run = first_run
        self.current_memory_id: str | None = None
        self.loaded_title = ""
        self.loaded_body = ""
        self.visible: dict[str, MemoryHit] = {}
        self._suspend_selection = False
        self._suspend_editor_events = False
        self._search_after: str | None = None
        self._autosave_after: str | None = None
        self._saving = False

        self.search_var = tk.StringVar()
        self.title_var = tk.StringVar()
        self.meta_var = tk.StringVar(value="내용을 입력하면 자동으로 저장됩니다.")
        self.status_var = tk.StringVar(value="로컬 암호화 저장소를 확인하는 중…")
        self.action_var = tk.StringVar(value="바로 입력하세요. 별도의 저장 방법을 배울 필요가 없습니다.")

        self._configure_window()
        self._build_menu()
        self._build_layout()
        self._bind_shortcuts()
        self.refresh_list()
        self.refresh_status()
        self.window.protocol("WM_DELETE_WINDOW", self.on_close)
        self.window.deiconify()
        self.window.after(250, self._show_first_run_welcome)

    def _configure_window(self) -> None:
        try:
            self.window.call("tk", "appname", APP_NAME)
        except tk.TclError:
            pass
        self.window.title(WINDOW_TITLE)
        self.window.geometry("1120x720")
        self.window.minsize(900, 600)
        self.window.option_add("*tearOff", False)
        try:
            self.window.call("tk", "scaling", 1.25)
        except tk.TclError:
            pass
        style = ttk.Style(self.window)
        if "aqua" in style.theme_names():
            style.theme_use("aqua")
        style.configure("Header.TLabel", font=("TkDefaultFont", 22, "bold"))
        style.configure("Subheader.TLabel", font=("TkDefaultFont", 11))
        style.configure("Title.TEntry", font=("TkDefaultFont", 15, "bold"))
        style.configure("Primary.TButton", font=("TkDefaultFont", 11, "bold"), padding=(14, 8))
        style.configure("Danger.TButton", padding=(12, 8))
        style.configure("Status.TLabel", font=("TkDefaultFont", 10))

    def _build_menu(self) -> None:
        menu = tk.Menu(self.window)
        app_menu = tk.Menu(menu)
        app_menu.add_command(label="Wiki Memory 정보", command=self.show_health)
        app_menu.add_separator()
        app_menu.add_command(label="Wiki Memory 종료", command=self.on_close, accelerator="⌘Q")
        menu.add_cascade(label="Wiki Memory", menu=app_menu)

        file_menu = tk.Menu(menu)
        file_menu.add_command(label="새 메모", command=self.new_note, accelerator="⌘N")
        file_menu.add_command(label="파일 추가…", command=self.import_file, accelerator="⌘O")
        file_menu.add_command(label="저장", command=self.save_current, accelerator="⌘S")
        file_menu.add_separator()
        file_menu.add_command(label="암호화 백업…", command=self.create_backup, accelerator="⌘B")
        file_menu.add_command(label="백업에서 복구…", command=self.restore_backup)
        menu.add_cascade(label="파일", menu=file_menu)

        edit_menu = tk.Menu(menu)
        edit_menu.add_command(label="검색", command=self.focus_search, accelerator="⌘F")
        edit_menu.add_separator()
        edit_menu.add_command(label="삭제", command=self.delete_current)
        menu.add_cascade(label="편집", menu=edit_menu)
        self.window.configure(menu=menu)

    def _build_layout(self) -> None:
        outer = ttk.Frame(self.window, padding=(22, 18, 22, 14))
        outer.pack(fill="both", expand=True)

        header = ttk.Frame(outer)
        header.pack(fill="x", pady=(0, 14))
        ttk.Label(header, text="Wiki Memory", style="Header.TLabel").pack(side="left")
        ttk.Label(
            header,
            text="내 Mac에만 저장되는 암호화 메모",
            style="Subheader.TLabel",
        ).pack(side="left", padx=(14, 0), pady=(9, 0))
        ttk.Label(header, textvariable=self.status_var, style="Status.TLabel").pack(
            side="right", pady=(8, 0)
        )

        pane = ttk.Panedwindow(outer, orient="horizontal")
        pane.pack(fill="both", expand=True)

        sidebar = ttk.Frame(pane, padding=(0, 0, 14, 0))
        editor = ttk.Frame(pane, padding=(14, 0, 0, 0))
        pane.add(sidebar, weight=1)
        pane.add(editor, weight=3)

        ttk.Label(sidebar, text="메모 검색").pack(anchor="w", pady=(0, 5))
        search_row = ttk.Frame(sidebar)
        search_row.pack(fill="x", pady=(0, 9))
        self.search_entry = ttk.Entry(
            search_row,
            textvariable=self.search_var,
            font=("TkDefaultFont", 12),
        )
        self.search_entry.pack(side="left", fill="x", expand=True)
        self.search_entry.bind("<KeyRelease>", self._schedule_search)
        ttk.Button(search_row, text="지우기", command=self.clear_search).pack(
            side="left", padx=(7, 0)
        )

        sidebar_actions = ttk.Frame(sidebar)
        sidebar_actions.pack(fill="x", pady=(0, 10))
        ttk.Button(
            sidebar_actions,
            text="＋ 새 메모",
            command=self.new_note,
            style="Primary.TButton",
        ).pack(side="left", fill="x", expand=True)
        ttk.Button(
            sidebar_actions,
            text="파일 추가…",
            command=self.import_file,
        ).pack(side="left", padx=(8, 0))

        tree_frame = ttk.Frame(sidebar)
        tree_frame.pack(fill="both", expand=True)
        self.memory_tree = ttk.Treeview(
            tree_frame,
            columns=("title", "updated"),
            show="headings",
            selectmode="browse",
        )
        self.memory_tree.heading("title", text="메모")
        self.memory_tree.heading("updated", text="수정일")
        self.memory_tree.column("title", width=230, minwidth=150, stretch=True)
        self.memory_tree.column("updated", width=88, minwidth=76, stretch=False, anchor="e")
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.memory_tree.yview)
        self.memory_tree.configure(yscrollcommand=scrollbar.set)
        self.memory_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self.memory_tree.bind("<<TreeviewSelect>>", self.on_memory_selected)

        ttk.Label(editor, text="제목").pack(anchor="w")
        self.title_entry = ttk.Entry(
            editor,
            textvariable=self.title_var,
            style="Title.TEntry",
        )
        self.title_entry.pack(fill="x", pady=(5, 12), ipady=5)
        self.title_var.trace_add("write", lambda *_: self._editor_changed())

        body_header = ttk.Frame(editor)
        body_header.pack(fill="x")
        ttk.Label(body_header, text="내용").pack(side="left")
        ttk.Button(body_header, text="메모 정보", command=self.show_citation).pack(side="right")

        body_frame = ttk.Frame(editor)
        body_frame.pack(fill="both", expand=True, pady=(5, 10))
        self.body_text = tk.Text(
            body_frame,
            wrap="word",
            undo=True,
            font=("TkDefaultFont", 13),
            padx=14,
            pady=12,
            borderwidth=1,
            relief="solid",
        )
        body_scroll = ttk.Scrollbar(body_frame, orient="vertical", command=self.body_text.yview)
        self.body_text.configure(yscrollcommand=body_scroll.set)
        self.body_text.pack(side="left", fill="both", expand=True)
        body_scroll.pack(side="right", fill="y")
        self.body_text.bind("<<Modified>>", self._editor_changed)

        ttk.Label(editor, textvariable=self.meta_var, style="Status.TLabel").pack(
            anchor="w", pady=(0, 9)
        )

        editor_actions = ttk.Frame(editor)
        editor_actions.pack(fill="x")
        ttk.Button(
            editor_actions,
            text="저장",
            command=self.save_current,
            style="Primary.TButton",
        ).pack(side="right")
        ttk.Button(
            editor_actions,
            text="삭제",
            command=self.delete_current,
            style="Danger.TButton",
        ).pack(side="right", padx=(0, 9))
        ttk.Button(editor_actions, text="백업", command=self.create_backup).pack(
            side="left"
        )
        ttk.Button(editor_actions, text="복구", command=self.restore_backup).pack(
            side="left", padx=(8, 0)
        )

        ttk.Separator(outer).pack(fill="x", pady=(12, 8))
        ttk.Label(outer, textvariable=self.action_var, style="Status.TLabel").pack(anchor="w")

    def _bind_shortcuts(self) -> None:
        for sequence, callback in (
            ("<Command-n>", self.new_note),
            ("<Command-o>", self.import_file),
            ("<Command-s>", self.save_current),
            ("<Command-f>", self.focus_search),
            ("<Command-b>", self.create_backup),
        ):
            self.window.bind_all(sequence, lambda event, fn=callback: self._shortcut(fn))
        self.window.bind_all("<Command-q>", lambda event: self._shortcut(self.on_close))

    @staticmethod
    def _shortcut(callback: Any) -> str:
        callback()
        return "break"

    def _show_first_run_welcome(self) -> None:
        """Open into a useful page instead of presenting an instruction dialog."""
        if self.first_run or not self.visible:
            self._set_editor(None)
            self.body_text.focus_set()
            self.action_var.set(
                "여기에 바로 입력하세요. 제목은 비워도 되고, 잠시 멈추면 자동 저장됩니다."
            )
            return
        first_id = next(iter(self.visible))
        try:
            hit = self.service.get(first_id)
        except LocalMemoryError:
            return
        self._set_editor(hit)
        self._suspend_selection = True
        try:
            self.memory_tree.selection_set(first_id)
            self.memory_tree.focus(first_id)
        finally:
            self._suspend_selection = False

    def _schedule_search(self, _event: tk.Event[Any] | None = None) -> None:
        if self._search_after is not None:
            self.window.after_cancel(self._search_after)
        self._search_after = self.window.after(220, self.refresh_list)

    def clear_search(self) -> None:
        self.search_var.set("")
        self.refresh_list()
        self.search_entry.focus_set()

    def focus_search(self) -> None:
        self.search_entry.focus_set()
        self.search_entry.selection_range(0, "end")

    def refresh_list(self, *, select_id: str | None = None) -> None:
        self._search_after = None
        try:
            hits = self.service.browse(self.search_var.get(), limit=100)
        except LocalMemoryError as exc:
            self.show_error(exc)
            return
        self.visible = {hit.memory_id: hit for hit in hits}
        self._suspend_selection = True
        try:
            for item in self.memory_tree.get_children():
                self.memory_tree.delete(item)
            for hit in hits:
                date = hit.updated_at[:10]
                self.memory_tree.insert(
                    "",
                    "end",
                    iid=hit.memory_id,
                    values=(hit.source_name, date),
                )
            if select_id and select_id in self.visible:
                self.memory_tree.selection_set(select_id)
                self.memory_tree.focus(select_id)
                self.memory_tree.see(select_id)
        finally:
            self._suspend_selection = False
        if hits:
            self.action_var.set(f"{len(hits)}개의 메모 · 입력한 변경은 자동 저장됩니다.")
        elif self.search_var.get().strip():
            self.action_var.set("검색 결과가 없습니다. 다른 단어를 입력해 보세요.")
        else:
            self.action_var.set("오른쪽에 바로 입력하면 첫 메모가 자동 저장됩니다.")

    def refresh_status(self) -> None:
        try:
            status = self.service.status()
        except LocalMemoryError as exc:
            self.status_var.set("점검 필요")
            self.action_var.set(f"점검 필요: {friendly_error(exc)}")
            return
        state = "정상" if status["operational_ready"] else "점검 필요"
        self.status_var.set(f"● {state} · 메모 {status['active_memories']}개")

    def _editor_body(self) -> str:
        return self.body_text.get("1.0", "end-1c")

    def _is_dirty(self) -> bool:
        return self.title_var.get() != self.loaded_title or self._editor_body() != self.loaded_body

    def _editor_changed(self, event: tk.Event[Any] | None = None) -> None:
        if event is not None:
            if not self.body_text.edit_modified():
                return
            self.body_text.edit_modified(False)
        if self._suspend_editor_events or self._saving:
            return
        if self._autosave_after is not None:
            self.window.after_cancel(self._autosave_after)
            self._autosave_after = None
        if not self._is_dirty():
            return
        body = self._editor_body()
        if not body.strip() and self.current_memory_id is None:
            self.action_var.set("내용을 입력하면 자동 저장됩니다.")
            return
        self.action_var.set("자동 저장 중…")
        self._autosave_after = self.window.after(900, self._autosave)

    def _autosave(self) -> None:
        self._autosave_after = None
        _ = self._save_editor(silent=True)

    def _confirm_discard(self) -> bool:
        if not self._is_dirty():
            return True
        if self._save_editor(silent=True):
            return True
        return messagebox.askyesno(
            "자동 저장 실패",
            "변경사항을 자동 저장하지 못했습니다. 변경을 버리고 계속할까요?",
            parent=self.window,
            default="no",
        )

    def _set_editor(self, hit: MemoryHit | None) -> None:
        if self._autosave_after is not None:
            self.window.after_cancel(self._autosave_after)
            self._autosave_after = None
        self._suspend_editor_events = True
        if hit is None:
            self.current_memory_id = None
            title = ""
            body = ""
            meta = "새 메모 · 내용을 입력하면 자동 저장 · 제목은 비워도 됩니다."
        else:
            self.current_memory_id = hit.memory_id
            title = hit.source_name
            body = hit.content
            meta = (
                f"저장 {hit.created_at.replace('T', ' ')[:16]} · "
                f"수정 {hit.updated_at.replace('T', ' ')[:16]} · 암호화 및 무결성 검증 완료"
            )
        self.title_var.set(title)
        self.body_text.delete("1.0", "end")
        self.body_text.insert("1.0", body)
        self.loaded_title = title
        self.loaded_body = body
        self.meta_var.set(meta)
        self.body_text.edit_modified(False)
        self._suspend_editor_events = False

    def on_memory_selected(self, _event: tk.Event[Any] | None = None) -> None:
        if self._suspend_selection:
            return
        selected = self.memory_tree.selection()
        if not selected:
            return
        memory_id = selected[0]
        if memory_id == self.current_memory_id:
            return
        if not self._confirm_discard():
            self._suspend_selection = True
            try:
                self.memory_tree.selection_remove(memory_id)
                if self.current_memory_id and self.current_memory_id in self.visible:
                    self.memory_tree.selection_set(self.current_memory_id)
            finally:
                self._suspend_selection = False
            return
        try:
            hit = self.service.get(memory_id)
        except LocalMemoryError as exc:
            self.show_error(exc)
            self.refresh_list()
            return
        self._set_editor(hit)
        self.action_var.set("메모를 열었습니다. 내용은 복호화 후 이 창에만 표시됩니다.")

    def new_note(self) -> None:
        if not self._confirm_discard():
            return
        self._suspend_selection = True
        try:
            selected = self.memory_tree.selection()
            if selected:
                self.memory_tree.selection_remove(*selected)
        finally:
            self._suspend_selection = False
        self._set_editor(None)
        self.body_text.focus_set()
        self.action_var.set("바로 입력하세요. 잠시 멈추면 자동 저장됩니다.")

    def save_current(self) -> None:
        _ = self._save_editor(silent=False)

    def _save_editor(self, *, silent: bool) -> bool:
        if self._saving:
            return False
        if self._autosave_after is not None:
            self.window.after_cancel(self._autosave_after)
            self._autosave_after = None
        title = self.title_var.get().strip()
        body = self._editor_body()
        if not body.strip():
            if self.current_memory_id is None:
                self.loaded_title = ""
                self.loaded_body = ""
                return True
            if not silent:
                messagebox.showinfo("내용을 입력하세요", "메모 내용은 비워 둘 수 없습니다.", parent=self.window)
            return False
        self._saving = True
        try:
            result = self.service.save(
                memory_id=self.current_memory_id,
                title=title,
                body=body,
            )
            memory_id = result["memory_id"]
            hit = self.service.get(memory_id)
        except (LocalMemoryError, OSError, ValueError) as exc:
            if silent:
                self.action_var.set(f"자동 저장 실패: {friendly_error(exc)}")
            else:
                self.show_error(exc)
            return False
        finally:
            self._saving = False
        self.current_memory_id = memory_id
        self._suspend_editor_events = True
        try:
            self.title_var.set(hit.source_name)
        finally:
            self._suspend_editor_events = False
        self.loaded_title = hit.source_name
        self.loaded_body = body
        self.meta_var.set(
            f"자동 저장됨 {datetime.now().strftime('%H:%M')} · 이 Mac에 암호화 및 무결성 검증"
        )
        self.refresh_list(select_id=memory_id)
        self.refresh_status()
        self.action_var.set("자동 저장 완료 · 앱을 바로 닫아도 안전합니다.")
        return True

    def import_file(self) -> None:
        path = filedialog.askopenfilename(
            parent=self.window,
            title="텍스트 또는 Markdown 파일 추가",
            filetypes=(
                ("텍스트와 Markdown", "*.txt *.md *.markdown"),
                ("모든 파일", "*"),
            ),
        )
        if not path:
            return
        try:
            result = self.service.import_file(path)
            hit = self.service.get(result["memory_id"])
        except (LocalMemoryError, OSError, ValueError) as exc:
            self.show_error(exc)
            return
        self.search_var.set("")
        self._set_editor(hit)
        self.refresh_list(select_id=hit.memory_id)
        self.refresh_status()
        self.action_var.set(f"‘{hit.source_name}’ 파일을 암호화해 추가했습니다.")

    def delete_current(self) -> None:
        if self.current_memory_id is None:
            messagebox.showinfo("삭제할 메모 없음", "먼저 삭제할 메모를 선택하세요.", parent=self.window)
            return
        if not messagebox.askyesno(
            "메모 완전히 삭제",
            "이 메모와 이전 버전을 검색에서 즉시 제거하고 암호화 키를 폐기합니다.\n"
            "이 작업은 앱 안에서 되돌릴 수 없습니다. 계속할까요?",
            parent=self.window,
            default="no",
        ):
            return
        memory_id = self.current_memory_id
        try:
            self.service.delete(memory_id)
        except (LocalMemoryError, OSError, ValueError) as exc:
            self.show_error(exc)
            return
        self._set_editor(None)
        self.refresh_list()
        self.refresh_status()
        self.action_var.set("삭제 완료 · 현재/이전 암호문과 해당 암호화 키를 폐기했습니다.")

    def show_citation(self) -> None:
        if self.current_memory_id is None:
            messagebox.showinfo("메모 정보 없음", "먼저 메모를 선택하세요.", parent=self.window)
            return
        try:
            citation = self.service.citation(self.current_memory_id)
        except LocalMemoryError as exc:
            self.show_error(exc)
            return
        messagebox.showinfo(
            "메모 근거",
            f"제목: {citation['source_name']}\n"
            f"최초 출처: {citation['origin_name']} ({citation['origin_kind']})\n"
            f"출처 범위: {citation['origin_locator_kind']}\n"
            f"저장 시각: {citation['created_at']}\n"
            f"수정 시각: {citation['updated_at']}\n"
            f"이전 버전: {citation['prior_versions']}개\n"
            "권한: 기존 암호화 Second Brain Core\n"
            "저장 상태: 정상 · 암호화 및 무결성 검증 완료\n\n"
            f"원본 확인 값:\n{citation['origin_sha256']}\n\n"
            f"현재 내용 확인 값:\n{citation['content_sha256']}",
            parent=self.window,
        )

    @staticmethod
    def _ask_passphrase(parent: tk.Misc, *, confirm: bool) -> str | None:
        first = simpledialog.askstring(
            "백업 암호",
            "백업을 보호할 암호를 입력하세요.\n12자 이상이며 잊으면 복구할 수 없습니다.",
            parent=parent,
            show="•",
        )
        if first is None:
            return None
        if len(first) < 12:
            messagebox.showerror("암호가 너무 짧음", "12자 이상의 암호를 사용하세요.", parent=parent)
            return None
        if confirm:
            second = simpledialog.askstring(
                "백업 암호 확인",
                "같은 암호를 한 번 더 입력하세요.",
                parent=parent,
                show="•",
            )
            if second is None:
                return None
            if first != second:
                messagebox.showerror("암호 불일치", "두 암호가 다릅니다.", parent=parent)
                return None
        return first

    def create_backup(self) -> None:
        try:
            DEFAULT_BACKUP_ROOT.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
        filename = f"Wiki Memory {datetime.now().strftime('%Y-%m-%d')}.wkbak"
        path = filedialog.asksaveasfilename(
            parent=self.window,
            title="암호화 백업 저장",
            initialdir=str(DEFAULT_BACKUP_ROOT),
            initialfile=filename,
            defaultextension=".wkbak",
            filetypes=(("Wiki Memory 백업", "*.wkbak"), ("모든 파일", "*")),
        )
        if not path:
            return
        destination = Path(path)
        overwrite = destination.exists()
        if overwrite and not messagebox.askyesno(
            "기존 백업 덮어쓰기",
            "같은 이름의 백업이 있습니다. 덮어쓸까요?",
            parent=self.window,
            default="no",
        ):
            return
        passphrase = self._ask_passphrase(self.window, confirm=True)
        if passphrase is None:
            return
        try:
            result = self.service.backup(
                destination,
                passphrase=passphrase,
                overwrite=overwrite,
            )
        except (LocalMemoryError, OSError, ValueError) as exc:
            self.show_error(exc)
            return
        self.action_var.set(f"암호화 백업 완료: {result['backup']}")
        messagebox.showinfo(
            "백업 완료",
            f"암호화 백업을 저장했습니다.\n\n{result['backup']}\n\n"
            "백업 암호는 앱에 저장되지 않습니다. 안전한 곳에 따로 보관하세요.",
            parent=self.window,
        )

    def restore_backup(self) -> None:
        if not self._confirm_discard():
            return
        path = filedialog.askopenfilename(
            parent=self.window,
            title="Wiki Memory 백업 선택",
            filetypes=(("Wiki Memory 백업", "*.wkbak"), ("모든 파일", "*")),
        )
        if not path:
            return
        passphrase = self._ask_passphrase(self.window, confirm=False)
        if passphrase is None:
            return
        if not messagebox.askyesno(
            "백업에서 복구",
            "현재 메모 저장소를 선택한 백업으로 교체합니다.\n"
            "현재 저장소는 자동으로 별도 보관됩니다. 계속할까요?",
            parent=self.window,
            default="no",
        ):
            return
        try:
            result = self.service.restore(path, passphrase=passphrase, replace=True)
        except (LocalMemoryError, OSError, ValueError) as exc:
            self.show_error(exc)
            return
        self.search_var.set("")
        self._set_editor(None)
        self.refresh_list()
        self.refresh_status()
        self.action_var.set("복구 완료 · 백업의 무결성과 암호를 확인한 뒤 저장소를 교체했습니다.")
        messagebox.showinfo(
            "복구 완료",
            "백업에서 메모를 복구했습니다.\n"
            f"기존 저장소 보관 위치: {result.get('replaced_workspace') or '없음'}",
            parent=self.window,
        )

    def show_health(self) -> None:
        try:
            status = self.service.status()
        except LocalMemoryError as exc:
            if messagebox.askyesno(
                "자동 복구 시도",
                f"{friendly_error(exc)}\n\n데이터 폴더 권한을 자동으로 복구할까요?",
                parent=self.window,
                default="yes",
            ):
                self.repair_permissions()
            return
        issues = status["issues"]
        details = (
            f"상태: {'정상' if status['operational_ready'] else '점검 필요'}\n"
            f"활성 메모: {status['active_memories']}개\n"
            f"삭제 기록: {status['forgotten_memories']}개\n"
            f"데이터베이스 무결성: {status['database_integrity']}\n"
            f"데이터 폴더 권한: {status['root_mode']}\n"
            f"암호화 키 권한: {status['key_mode']}\n\n"
            "외부 네트워크: 사용 안 함\n"
            "외부 AI 모델: 사용 안 함\n"
            "자동 수집·외부 전송: 사용 안 함"
        )
        if issues:
            details += "\n\n문제:\n- " + "\n- ".join(str(issue) for issue in issues)
            if messagebox.askyesno(
                "상태 점검",
                details + "\n\n보호 권한을 자동 복구할까요?",
                parent=self.window,
                default="yes",
            ):
                self.repair_permissions()
        else:
            messagebox.showinfo("상태 점검", details, parent=self.window)

    def repair_permissions(self) -> None:
        try:
            status = DesktopMemoryService.repair_workspace_permissions(self.service.root)
            self.service = DesktopMemoryService(self.service.root)
        except (LocalMemoryError, OSError, ValueError) as exc:
            self.show_error(exc)
            return
        self.refresh_status()
        messagebox.showinfo(
            "자동 복구 완료",
            "데이터 폴더와 암호화 키의 보호 권한을 복구했습니다.\n"
            f"현재 상태: {status['state']}",
            parent=self.window,
        )

    def show_error(self, exc: BaseException) -> None:
        messagebox.showerror("작업을 완료하지 못했습니다", friendly_error(exc), parent=self.window)
        self.action_var.set(f"작업 실패: {friendly_error(exc)}")

    def on_close(self) -> None:
        if not self._confirm_discard():
            return
        self.window.destroy()


def _open_with_repair(root: Path, parent: tk.Tk) -> tuple[DesktopMemoryService, bool] | None:
    try:
        opened = DesktopMemoryService.open_or_initialize(root)
        return opened.service, opened.first_run
    except LocalMemoryError as exc:
        if root.exists() and messagebox.askyesno(
            "데이터 폴더 자동 복구",
            f"{friendly_error(exc)}\n\n보호 권한을 자동으로 복구하고 다시 열까요?",
            parent=parent,
            default="yes",
        ):
            try:
                DesktopMemoryService.repair_workspace_permissions(root)
                opened = DesktopMemoryService.open_or_initialize(root)
                return opened.service, opened.first_run
            except (LocalMemoryError, OSError, ValueError) as repair_exc:
                messagebox.showerror(
                    "자동 복구 실패",
                    friendly_error(repair_exc),
                    parent=parent,
                )
                return None
        messagebox.showerror("Wiki Memory를 열 수 없음", friendly_error(exc), parent=parent)
        return None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Wiki Memory native desktop app")
    parser.add_argument("--root", type=Path, default=DEFAULT_DATA_ROOT)
    parser.add_argument("--check", action="store_true", help="run a headless installation check")
    parser.add_argument("--read-only-request", help=argparse.SUPPRESS)
    parser.add_argument("--demo", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--ui-smoke", action="store_true", help=argparse.SUPPRESS)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = args.root.expanduser()
    if args.check:
        try:
            result = check_environment(root)
        except (LocalMemoryError, OSError, ValueError) as exc:
            print(json.dumps({"status": "ERROR", "message": str(exc)}, ensure_ascii=False))
            return 2
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0 if result["operational_ready"] else 1
    if args.read_only_request is not None:
        try:
            request = json.loads(args.read_only_request)
            store = DesktopMemoryService(root).store
            try:
                result = ReadOnlyMemoryTools(store).handle(request)
            finally:
                store.close()
        except (json.JSONDecodeError, LocalMemoryError, OSError, ValueError) as exc:
            print(json.dumps({"status": "ERROR", "message": str(exc)}, ensure_ascii=False))
            return 2
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0

    if tk is None:
        print(
            "Wiki Memory GUI could not start: this Python runtime has no Tk support",
            file=sys.stderr,
        )
        return 2
    try:
        window = tk.Tk()
    except tk.TclError as exc:
        print(f"Wiki Memory GUI could not start: {exc}", file=sys.stderr)
        return 2
    window.withdraw()
    opened = _open_with_repair(root, window)
    if opened is None:
        window.destroy()
        return 2
    service, first_run = opened
    if args.demo and not service.browse():
        service.save(
            memory_id=None,
            title="고객 회의",
            body="고객 회의에서 10월 복구 일정을 확정했습니다.",
        )
        service.save(
            memory_id=None,
            title="보안 운영 원칙",
            body="민감한 업무 기록은 외부 모델에 보내지 않고 이 Mac에 암호화해 저장합니다.",
        )
        service.save(
            memory_id=None,
            title="서버 점검",
            body="금요일 오후에 HCI 서버 백업과 복구 상태를 확인합니다.",
        )
        first_run = False
    if args.ui_smoke:
        first_run = False
    _ = WikiMemoryApp(window, service, first_run=first_run)
    if args.ui_smoke:
        window.after(700, window.destroy)
    window.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
