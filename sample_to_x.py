def sample_to_x(sample, access_points):
    sample_data = []
    for addr in access_points:
        if addr in sample:
            assert len(sample[addr]) == 3
            sample_data.extend(sample[addr])
        else:
            sample_data.extend([float('NaN'), float('NaN'), float('NaN')])
    return sample_data
