import sqlite3
import unittest

import app


class AutofindParserTests(unittest.TestCase):
  def test_parse_autofind(self):
    text = """
Number              : 1
F/S/P               : 0/12/0
Ont SN              : 4857544372249FAF (HWTC-72249FAF)
Ont EquipmentID     : EG8145X6-10
-----------------------------------------------
The number of GPON autofind ONT is 1
"""
    self.assertEqual(app.parse_autofind(text), {
        "count": 1,
        "onts": [{"sfp": "0/12/0", "serial": "4857544372249FAF"}],
    })

class AlertAndReportTests(unittest.TestCase):
    def setUp(self):
        self.old_config = app.OLT_CONFIG
        app.OLT_CONFIG = {"name":"Teste","telegram_chat_id":"-123"}

    def tearDown(self):
        app.OLT_CONFIG = self.old_config

    def test_threshold_and_online_filter(self):
        onts = [{"pon_index":"4194312192","ont_number":n,"description":f"Cliente {n}",
                 "serial_text":f"SERIAL{n}","rx_power":-2700,"status":"online"} for n in range(5)]
        onts += [{"pon_index":"4194312192","ont_number":5,"description":"Offline",
                  "rx_power":-3000,"status":"offline"},
                 {"pon_index":"4194312192","ont_number":6,"description":"Bom",
                  "rx_power":-2699,"status":"online"}]
        data = {"collected_at":"2026-09-21T12:00:00+00:00","pons":[{"index":"4194312192","sfp":"0/1/0"}],"onts":onts}
        alerts = app.low_signal_alerts(data)
        self.assertEqual(len(alerts),1)
        self.assertIn("Clientes afetados: 5 de 7 (71%)",alerts[0][3])
        self.assertIn("0/1/0",alerts[0][3])
        self.assertNotIn("Offline",alerts[0][3])
        self.assertIsNone(alerts[0][4])
        self.assertIn("Host: Teste",alerts[0][3])
        data["onts"] = onts[:4] + [{"pon_index":"4194312192","ont_number":n+10,"status":"online","rx_power":-1000} for n in range(20)]
        self.assertEqual(app.low_signal_alerts(data),[])

    def test_message_parts_stay_within_telegram_limit(self):
        data = {"collected_at":"2026-09-21T12:00:00+00:00","pons":[{"index":"4194312192","sfp":"0/1/0"}],
                "onts":[{"pon_index":"4194312192","ont_number":n,"description":"Nome grande "*10,
                         "serial_text":f"SERIAL{n}","rx_power":-2800,"status":"online"} for n in range(100)]}
        alerts = app.low_signal_alerts(data)
        self.assertEqual(len(alerts),1)
        self.assertLess(len(alerts[0][3]),4096)
        self.assertIsNone(alerts[0][5])

    def test_outage_alerts_are_grouped_by_board_and_reason(self):
        pons = [{"index":"a","sfp":"0/1/0"},{"index":"b","sfp":"0/1/1"}]
        dying = [{"pon_index":"a","ont_number":n,"description":"Cliente","serial_text":str(n),"status":"offline","disconnect_reason":13} for n in range(5)]
        broken = [{"pon_index":"b","ont_number":n,"description":"Cliente","serial_text":str(n),"status":"offline","disconnect_reason":1} for n in range(5)]
        alerts = app.outage_alerts({"collected_at":"agora","pons":pons,"onts":dying+broken})
        self.assertEqual(len(alerts),2)
        self.assertTrue(any("Possível queda de energia" in item[3] for item in alerts))
        self.assertTrue(any("Possível rompimento" in item[3] for item in alerts))
        self.assertTrue(all("Placa:" not in item[3] for item in alerts))
        self.assertTrue(any("Dying-gasp (13): 5" in item[3] for item in alerts))

    def test_outage_does_not_accumulate_separate_pons(self):
        pons = [{"index":str(n),"sfp":f"0/2/{n}"} for n in range(5)]
        onts = [{"pon_index":str(n),"ont_number":1,"status":"offline","disconnect_reason":2} for n in range(5)]
        onts += [{"pon_index":str(n),"ont_number":m+2,"status":"online"} for n in range(5) for m in range(9)]
        self.assertEqual(app.outage_alerts({"collected_at":"agora","pons":pons,"onts":onts}), [])

    def test_percentage_threshold_is_twenty_percent(self):
        pons = [{"index":"a","sfp":"0/0/1"}]
        onts = [{"pon_index":"a","ont_number":1,"status":"offline","disconnect_reason":13}]
        onts += [{"pon_index":"a","ont_number":n+2,"status":"online"} for n in range(8)]
        self.assertEqual(app.outage_alerts({"collected_at":"agora","pons":pons,"onts":onts}), [])
        onts.append({"pon_index":"a","ont_number":11,"status":"offline","disconnect_reason":13})
        self.assertEqual(len(app.outage_alerts({"collected_at":"agora","pons":pons,"onts":onts})), 1)

    def test_report_has_spacing_without_repeated_pon(self):
        data = {"host":"10.0.0.1","pon_number":"0/1/0","pon_label":"0/1/0","collected_at":"hoje",
                "onts":[{"pon_index":"4194312192","ont_number":1,"description":"Cliente",
                         "serial_text":"SERIAL","rx_power":-2700,"temperature":32,"status":"online"}]}
        report = app.onts_text(data)
        self.assertIn("PON S/F/P: 0/1/0",report)
        self.assertIn("ONT 1 | Cliente",report)
        self.assertNotIn("PON 0/1/0 / ONT",report)
        self.assertIn("Temperatura: 32 °C\r\n\r\n",report)

    def test_uptime_in_portuguese(self):
        self.assertEqual(app.uptime_pt("(9006100)"), "1 dia 1h 01min")
        self.assertEqual(app.uptime_pt(None), "Sem leitura")

    def test_alert_event_is_sent_once_then_updates_and_resolves(self):
        db = sqlite3.connect(":memory:")
        db.executescript(app.SCHEMA)
        initial = ("pon:0/0/1:energia",1,"-1","Alerta\nHost: Teste\nPON: 0/0/1\nClientes afetados: 5",None,None)
        app.queue_alert_events(db,1,"2026-09-21T12:00:00+00:00",[initial])
        app.queue_alert_events(db,2,"2026-09-21T12:05:00+00:00",[initial])
        self.assertEqual(db.execute("SELECT count(*) FROM telegram_alerts").fetchone()[0],1)
        increased = (*initial[:3],"Alerta\nHost: Teste\nPON: 0/0/1\nClientes afetados: 7",None,None)
        app.queue_alert_events(db,3,"2026-09-21T12:10:00+00:00",[increased])
        messages = [row[0] for row in db.execute("SELECT message FROM telegram_alerts ORDER BY id")]
        self.assertEqual(len(messages),2)
        self.assertIn("eram 5, agora 7",messages[-1])
        app.queue_alert_events(db,4,"2026-09-21T12:15:00+00:00",[])
        self.assertEqual(db.execute("SELECT count(*) FROM telegram_alerts").fetchone()[0],3)
        resolution = db.execute("SELECT message FROM telegram_alerts ORDER BY id DESC LIMIT 1").fetchone()[0]
        self.assertIn("Problema resolvido",resolution)
        self.assertIn("Problema iniciado em: 21-09-2026 09:00",resolution)
        self.assertIn("Problema resolvido em: 21-09-2026 09:15",resolution)
        self.assertEqual(db.execute("SELECT started_at FROM alert_states WHERE alert_key=?", (initial[0],)).fetchone()[0], "2026-09-21T12:00:00+00:00")

if __name__ == "__main__": unittest.main()
