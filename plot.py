import datetime

import dash
from dash import dcc, html, ctx, Input, Output
import plotly.graph_objs as go
import matplotlib.pyplot as plt

from cache import Cache
from capture import CaptureThreadFactory, HOSTNAMES, TsharkLine
from utils import filter_items

start_ts = datetime.datetime.now()

# Initialize the Dash app
app = dash.Dash(__name__)

# Define the layout of the web application
app.layout = html.Div([
    dcc.Store(id="store", storage_type='session'),
    dcc.Input(
        id="session-filter",
        type="text",
        placeholder="Sessions",
        persistence=True
    ),
    dcc.Input(
        id="packet-filter",
        type="text",
        placeholder="Packet sizes",
        persistence=True
    ),
    html.Button(
        "Clear cache",
        id="clear-cache",
        type="button",
        n_clicks=0
    ),
    html.Button(
        "",
        id="capture-action",
        type="button",
        n_clicks=0
    ),
    dcc.Graph(id='live-packet-size-graph'),
    dcc.Interval(
        id='interval-component',
        interval=1000,  # Update every 1 second
        n_intervals=0
    ),
    html.Div(id="dummy")
])


def create_metadata(packet: TsharkLine) -> str:
    md = {
        "client_port": packet.port_client,
        "server_ip": packet.ip_server,
        "server_port": packet.port_server,
        "server_name": HOSTNAMES.get(packet.tcp_stream, "")
    }
    return "<br>".join(f"<b>{key}</b>: {val}" for key, val in md.items())


def create_legend_name(port_client: int, ip_server: str, port_server: int, tcp_stream: int | None) -> str:
    s = f':{port_client}<->{ip_server}:{port_server}'
    if tcp_stream and tcp_stream in HOSTNAMES:
        s += f' ({HOSTNAMES[tcp_stream]})'
    return s


@app.callback(Output('dummy', 'children'),
              Input('clear-cache', 'n_clicks'),
              prevent_initial_call=True)
def clear_cache(clear_cache_nclicks: int):
    print(ctx.triggered_id)
    Cache().clear_all()


class CaptureState:
    NOT_STARTED = 0
    RUNNING = 1
    PAUSED = 2


current_capture_state = CaptureState.NOT_STARTED


@app.callback(Output('capture-action', 'children'),
              Input('capture-action', 'n_clicks'))
def start_stop_capture(n_clicks: int):
    global current_capture_state

    capture_thread_factory = CaptureThreadFactory()
    if CaptureState.NOT_STARTED == current_capture_state:
        if ctx.triggered_id:  # button clicked
            capture_thread_factory.new(cache=Cache())
            current_capture_state = CaptureState.RUNNING

    elif CaptureState.PAUSED == current_capture_state:
        if ctx.triggered_id:  # button clicked
            capture_thread_factory.new(cache=Cache())
            current_capture_state = CaptureState.RUNNING

    elif CaptureState.RUNNING == current_capture_state:
        if ctx.triggered_id:  # button clicked
            capture_thread_factory.kill()
            current_capture_state = CaptureState.PAUSED

    return ["Start capture", "Pause capture", "Resume capture"][current_capture_state]


# Define callback to update the live plot
@app.callback(Output('live-packet-size-graph', 'figure'),
              Input('interval-component', 'n_intervals'),
              Input('live-packet-size-graph', 'relayoutData'),
              Input('session-filter', 'value'),
              Input('packet-filter', 'value'),
              prevent_initial_call=True)
def update_live_plot(intervals: int | None, relayout_data: dict | None,
                     session_filter: str | None, packet_filter: str | None):
    cache = Cache()

    # Create a colormap with unique colors for each ID
    num_unique_ids = len(cache.sessions)
    colormap = plt.colormaps.get_cmap('plasma')  # Use the 'viridis' colormap

    # Generate a unique color for each ID
    id_to_color = {}
    for i, session_key in enumerate(cache.sessions.keys()):
        r, g, b, a = colormap(i / num_unique_ids)
        id_to_color[session_key] = f'rgba({r * 255}, {g * 255}, {b * 255}, {a * .5})'

    # Create a list of traces, one for each unique ID
    traces = []
    for session_key in cache.sessions.keys():
        first_packet: TsharkLine = cache.sessions[session_key][0]
        legend_name = create_legend_name(port_client=first_packet.port_client, ip_server=first_packet.ip_server,
                                         port_server=first_packet.port_server, tcp_stream=first_packet.tcp_stream)
        if session_filter and session_filter not in legend_name:  # filter results from the session-filter
            continue

        packets = cache.sessions[session_key]
        if packet_filter:
            show_tcp_lens = filter_items(packet_filter)
            # Filter data points for the current ID
            x_values = [p.ts for p in packets if p.tcp_len in show_tcp_lens]
            y_values = [p.tcp_len for p in packets if p.tcp_len in show_tcp_lens]
            metadata = [create_metadata(p) for p in packets if p.tcp_len in show_tcp_lens]
        else:
            x_values = [p.ts for p in packets]
            y_values = [p.tcp_len for p in packets]
            metadata = [create_metadata(p) for p in packets]
        trace = go.Scatter(
            x=x_values,
            y=y_values,
            mode='markers',  # Use 'markers' mode for scatter plot
            name=legend_name,  # Set the name to the ID for the legend
            marker=dict(
                size=8,  # Adjust the size of the markers
                color=id_to_color[session_key]  # Assign colors based on IDs
            ),
            text=metadata
        )
        traces.append(trace)

    # zoom is not used - update max x to current time + 5 seconds
    xaxis_range = (
        start_ts, datetime.datetime.now() + datetime.timedelta(
            seconds=5)) if relayout_data and 'autosize' in relayout_data else None

    layout = go.Layout(
        title=f'Live Packet Size vs. Time ({cache.total_packets} packets)',
        xaxis=dict(title='Time (s)', range=xaxis_range),
        yaxis=dict(title='Packet Size (bytes)'),
        showlegend=True,
        uirevision='live'  # Add the uirevision attribute
    )
    figure = go.Figure(data=traces, layout=layout)

    return figure


if __name__ == '__main__':
    app.run(debug=True)
