import sys
from PyQt5.QtWidgets import QApplication
from ui.main_window import MainWindow

def run_app():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())