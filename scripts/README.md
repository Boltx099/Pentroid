# Dev scripts

Both scripts render the GUI with QT_QPA_PLATFORM=offscreen (no display
needed) and save PNG screenshots -- useful for catching layout bugs like
the top-bar overlap without needing eyes on a live window.

    QT_QPA_PLATFORM=offscreen python3 scripts/dev_screenshot.py out.png
    QT_QPA_PLATFORM=offscreen python3 scripts/dev_multi_screenshot.py   # one PNG per page in /home/claude
