Was steht wo:
-log.txt -> Reiner log vom Server beim Testen
-proveLog.txt -> Reine Ausgabe vom Testprotokoll
-logComb.txt -> Beides Kombiniert, um Verknüpfungen eventuell erkennen zu können


TODO:
-Korrekter Status muss ausgegeben werden(Datei nicht exitsten -> 404, alles gut -> 200, ...)
-Datum nicht korrekt formatiert
-HEAD Verarbeitung fehlt noch komplett
-Testskript läuft nicht durcH, hängt in 01method bei head -> wird wohl durch implementierung behoben
-Content-Length immer gleich
-Data Range fehlt
-02basic müsste durchlaufen, wenn head implementiert
-02mime wenn staus korrekt
-02zero vermutich dateirange kritisch
-03moved -> status 301
-04modsince -> modified since muss implementiert werden
-05cgi versteh ich nicht
