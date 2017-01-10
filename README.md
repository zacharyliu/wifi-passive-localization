# wifi-passive-localization

Implementation of [device-free passive localization](https://dl.acm.org/citation.cfm?id=1287880). This concept refers to the ability to determine the location of a human in an environment using passive monitoring of Wi-Fi access point signal strengths over time. As a human moves through the environment, they cause fluctuations in the signal strengths which can be observed and classified.

Sample code is included to capture packets on a Linux device, pre-process captured packets, and train a machine learning model to classify future captured data. Two Jupyter notebooks are included with the code used to generate the graphs in the submitted paper.

Created for a Computer Science Independent Work project at Princeton University in Fall 2016, as part of the [COS IW 02 Policy Issues in the Internet of Things](https://www.cs.princeton.edu/ugrad/independent-work/independent-work-seminar-offerings-fall-2016) seminar.

## Usage
1. On a Linux machine, run `capture.py -d duration label` (as root) to capture `duration` seconds of packets to a file `packets/packets-<label>-<timestamp>.pkl`.
2. Generate training data for the model with `training_data.py label data`. Pass the name of the saved packets files and their associated category labels as the `data` parameter. Multiple files can be provided for each label. (Example: `0 packets/packets-0-0.pkl packets/packets-0-1.pkl 1 packets/packets-1-0.pkl packets/packets-1-1.pkl`) This saves a file `data/training-data-<label>.pkl`.
3. Train the model with `train.py data [-l label] [--plot]`. If `--plot` is specified, a graphical visualization of the training data will be displayed. Otherwise, if `-l label` is specified, the trained model will be saved to `models/model-<label>.pkl`. 
4. Run `classify_packets.py model packets` to run the model file `model` on the packets file `packets`. The script will output a predicted category label for each sample.
5. Run `classify_realtime.py model` (as root) to use the model file `model` to classify packets in real-time.
