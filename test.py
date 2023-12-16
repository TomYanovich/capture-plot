import numpy as np
import pandas as pd
import stumpy

if __name__ == "__main__":
    your_time_series = pd.Series(data=[5, 0, 1.1, 2, 3, 0, 1, 2.1, 3, 0])
    # print(your_time_series)
    window_size = 4  # Approximately, how many data points might be found in a pattern

    mp = stumpy.stump(your_time_series.astype(np.float64).to_numpy(), m=window_size)
    idx = np.argmin(mp)
    motif_idx = np.argsort(mp[:, 0])[0]
    print(f"The motif is located at index {motif_idx}")
    nearest_neighbor_idx = mp[motif_idx, 1]
    print(f"The nearest neighbor is located at index {nearest_neighbor_idx}")
