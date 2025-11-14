#Training of model needs to be executed manually because its not necessary to train it each time when analyzing logs
#python3 3TrainModelFromFeatures.py 
cp /var/log/suricata/eve.json ./actualEve.json
python3 1filterAlertsFromEve.py actualEve.json > actualAlerts.json
python3 2filterFeaturesFromAlerts.py actualAlerts.json > actualFeatures.json
python3 4checkNewEntryForAnomaly.py actualFeatures.json