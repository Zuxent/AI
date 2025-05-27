def startup():
    """
    This function starts a Tkinter GUI with a live-updating matplotlib graph.
    """
    import tkinter as tk
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    from matplotlib.figure import Figure
    import numpy as np

    import time

    # Create the main window
    root = tk.Tk()
    root.title("Live Graph - AI Assistant")
    root.geometry("600x400")

    # Create a matplotlib figure
    fig = Figure(figsize=(5, 3), dpi=100)
    ax = fig.add_subplot(111)
    x_vals = list(range(100))
    y_vals = [0] * 100
    line, = ax.plot(x_vals, y_vals)
    ax.set_ylim(-1.5, 1.5)

    # Embed the matplotlib figure in tkinter
    canvas = FigureCanvasTkAgg(fig, master=root)
    canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=True)
    canvas.draw()

    # Function to update the graph
    def update_graph():
        nonlocal y_vals
        y_vals = y_vals[1:] + [np.sin(time.time())]
        line.set_ydata(y_vals)
        canvas.draw()
        root.after(1000, update_graph)  # Schedule next update in 1000ms

    # Start updating the graph
    update_graph()

    # Start the main loop
    root.mainloop()
