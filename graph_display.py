import tkinter as tk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt

def show_graph(data):
    window = tk.Tk()
    window.title("Computation Time Graphs")

    fig, ax = plt.subplots()

    algorithms = list(data.keys())
    times_in_ms = [time * 1000.0 for time in data.values()]
  

    ax.bar(algorithms, times_in_ms, color=['green', 'red', 'purple'])
    ax.set_xlabel('Algorithms')
    ax.set_ylabel('Time(in seconds)')  # Update the label to milliseconds
    ax.set_title('Computation Time for Different Algorithms')

    canvas = FigureCanvasTkAgg(fig, master=window)
    canvas.draw()
    canvas.get_tk_widget().pack()

    window.mainloop()