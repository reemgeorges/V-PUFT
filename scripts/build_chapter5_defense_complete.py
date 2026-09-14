from __future__ import annotations

from pathlib import Path
from html import escape
from hashlib import sha256
import re

ROOT = Path.cwd()
OLD = ROOT / "docs/final_chapter5/VPUFT_Chapter5_Arabic_Complete.html"
NEW = ROOT / "docs/final_chapter5/VPUFT_Chapter5_Arabic_Defense_Complete.html"

if not OLD.exists():
    raise SystemExit(f"Approved source is missing: {OLD}")

old_bytes = OLD.read_bytes()
old_sha = sha256(old_bytes).hexdigest()
old_html = old_bytes.decode("utf-8")

VEHICLES = [20, 40, 60, 80, 100]

TOPOLOGIES = {
    "Smoke": {
        "ar": "سيناريو الاختبار الدخاني المصغّر",
        "meaning": (
            "سيناريو صغير للتحقق من سلامة خط المعالجة قبل الانتقال إلى شبكات "
            "مرورية أعقد. لا تعني كلمة Smoke وجود دخان فعلي؛ بل تعني اختباراً "
            "تشغيلياً سريعاً ومحدود التعقيد."
        ),
        "workload": {
            "cases": [133.0, 249.7, 340.8, 409.0, 454.4],
            "v2x": [1904.0, 3491.3, 4524.2, 5165.0, 5490.5],
            "detections": [16722.7, 33946.2, 44747.4, 51506.4, 54913.5],
        },
        "classification": {
            "D": {
                "Precision": [0.9088, 0.8934, 0.8602, 0.8490, 0.8358],
                "Recall": [0.5938, 0.5860, 0.5544, 0.5073, 0.4480],
                "FRR": [0.0085, 0.0101, 0.0101, 0.0077, 0.0064],
                "F1": [0.7152, 0.7072, 0.6738, 0.6338, 0.5827],
                "MCC": [0.7063, 0.6939, 0.6644, 0.6349, 0.5928],
            },
            "C": {
                "Precision": [0.9088, 0.8934, 0.8602, 0.8490, 0.8358],
                "Recall": [0.5938, 0.5860, 0.5544, 0.5073, 0.4480],
                "FRR": [0.0085, 0.0101, 0.0101, 0.0077, 0.0064],
                "F1": [0.7152, 0.7072, 0.6738, 0.6338, 0.5827],
                "MCC": [0.7063, 0.6939, 0.6644, 0.6349, 0.5928],
            },
        },
        "p95_d": [14314.67, 14538.44, 14580.05, 14514.59, 14489.20],
        "p95_c200": [14347.82, 14443.45, 14508.15, 14525.41, 14548.84],
        "breakeven": [166.85, 294.99, 271.90, 189.19, 140.37],
        "inside": [True, False, False, True, True],
        "ops": {
            "D": {
                "messages": [24.80, 24.06, 22.22, 20.62, 19.40],
                "bytes": [26572.75, 24228.98, 20933.96, 18018.16, 16308.32],
                "queue": [4291.80, 4570.94, 4774.49, 4911.35, 4930.86],
                "pdr": [0.98134, 0.98129, 0.98083, 0.98084, 0.98056],
                "cpu": [2.567, 4.252, 4.944, 3.691, 3.794],
                "memory": [3821.6, 6750.8, 8632.0, 9850.1, 10457.7],
            },
            "C": {
                "messages": [33.20, 31.98, 30.43, 29.33, 28.17],
                "bytes": [23370.68, 22511.46, 21424.72, 20646.23, 19829.27],
                "queue": [5636.32, 5951.42, 5989.22, 5926.17, 5832.59],
                "pdr": [0.98082, 0.98084, 0.98046, 0.98060, 0.98042],
                "cpu": [1.711, 3.105, 3.739, 3.084, 3.317],
                "memory": [3975.8, 7086.6, 9170.9, 10571.4, 11288.7],
            },
        },
        "means": {
            "p95": 12.6582, "messages": -8.3999, "bytes": -344.0389,
            "queue": -1171.2564, "cpu": 0.8581, "memory": -516.2260,
        },
    },

    "Corridor": {
        "ar": "الممر الطرقي",
        "meaning": (
            "طريق ممتد تكون فيه حركة المركبات واتصالاتها موزعة طولياً. يفيد في "
            "دراسة تغير الجوار اللاسلكي وانتقال المركبات بين نطاقات وحدات الطريق."
        ),
        "workload": {
            "cases": [133.0, 266.0, 392.8, 502.5, 602.6],
            "v2x": [1904.0, 3804.0, 5586.8, 7054.5, 8251.3],
            "detections": [18428.8, 41018.9, 60323.3, 76135.1, 88974.5],
        },
        "classification": {
            "D": {
                "Precision": [0.9215, 0.9174, 0.9231, 0.9134, 0.9084],
                "Recall": [0.7125, 0.7937, 0.7201, 0.6849, 0.6918],
                "FRR": [0.0085, 0.0098, 0.0088, 0.0096, 0.0094],
                "F1": [0.8019, 0.8507, 0.8089, 0.7826, 0.7853],
                "MCC": [0.7879, 0.8350, 0.7927, 0.7657, 0.7696],
            },
            "C": {
                "Precision": [0.9215, 0.9174, 0.9231, 0.9134, 0.9084],
                "Recall": [0.7125, 0.7937, 0.7201, 0.6849, 0.6918],
                "FRR": [0.0085, 0.0098, 0.0088, 0.0096, 0.0094],
                "F1": [0.8019, 0.8507, 0.8089, 0.7826, 0.7853],
                "MCC": [0.7879, 0.8350, 0.7927, 0.7657, 0.7696],
            },
        },
        "p95_d": [14412.23, 14772.67, 15163.82, 15329.35, 15535.36],
        "p95_c200": [14345.20, 14457.61, 14563.11, 14654.19, 14752.60],
        "breakeven": [267.03, 515.06, 800.71, 875.16, 982.76],
        "inside": [False, False, False, False, False],
        "ops": {
            "D": {
                "messages": [32.59, 32.57, 31.99, 31.51, 30.44],
                "bytes": [37550.00, 36063.89, 34237.28, 32067.50, 30553.19],
                "queue": [4275.94, 4813.98, 5041.66, 5154.86, 5190.35],
                "pdr": [0.98028, 0.98055, 0.98008, 0.97994, 0.97988],
                "cpu": [2.258, 4.455, 6.522, 7.627, 8.848],
                "memory": [4795.0, 9354.8, 13593.8, 17100.1, 19809.7],
            },
            "C": {
                "messages": [41.74, 41.56, 41.11, 40.39, 39.21],
                "bytes": [29384.32, 29258.35, 28938.72, 28435.61, 27603.39],
                "queue": [5655.43, 5967.56, 6057.76, 6172.85, 6191.00],
                "pdr": [0.97997, 0.98019, 0.98008, 0.98014, 0.98006],
                "cpu": [1.409, 2.848, 4.367, 5.169, 6.091],
                "memory": [4919.5, 9770.3, 14298.8, 17883.5, 20770.0],
            },
        },
        "means": {
            "p95": 488.1450, "messages": -8.9780, "bytes": 5370.2943,
            "queue": -1113.5654, "cpu": 1.9650, "memory": -597.7213,
        },
    },

    "Intersection": {
        "ar": "التقاطع المروري",
        "meaning": (
            "تقاطع تتلاقى عنده مسارات مختلفة، فتتغير مجموعات المركبات المرئية "
            "وفترات التقارب بسرعة. وهو أكثر السيناريوهات حملاً من حيث الرسائل لكل قرار."
        ),
        "workload": {
            "cases": [117.6, 242.0, 363.7, 469.9, 569.9],
            "v2x": [1697.4, 3470.2, 5168.6, 6574.9, 7731.9],
            "detections": [16514.7, 41715.8, 64828.9, 83418.3, 98498.8],
        },
        "classification": {
            "D": {
                "Precision": [0.9144, 0.9171, 0.9232, 0.9122, 0.8990],
                "Recall": [0.6687, 0.7906, 0.7377, 0.7050, 0.6677],
                "FRR": [0.0098, 0.0110, 0.0099, 0.0106, 0.0106],
                "F1": [0.7722, 0.8486, 0.8197, 0.7953, 0.7662],
                "MCC": [0.7545, 0.8309, 0.8013, 0.7763, 0.7489],
            },
            "C": {
                "Precision": [0.9144, 0.9171, 0.9220, 0.9128, 0.8992],
                "Recall": [0.6687, 0.7906, 0.7259, 0.7098, 0.6691],
                "FRR": [0.0098, 0.0110, 0.0099, 0.0106, 0.0106],
                "F1": [0.7722, 0.8486, 0.8117, 0.7985, 0.7672],
                "MCC": [0.7545, 0.8309, 0.7933, 0.7795, 0.7498],
            },
        },
        "p95_d": [14528.79, 15220.77, 15716.15, 15899.68, 16021.97],
        "p95_c200": [14370.30, 14506.04, 14642.10, 14777.52, 14869.58],
        "breakeven": [358.50, 914.73, 1274.05, 1322.16, 1352.39],
        "inside": [False, False, False, False, False],
        "ops": {
            "D": {
                "messages": [61.15, 62.72, 62.00, 60.81, 58.42],
                "bytes": [64350.59, 68261.19, 67826.14, 62065.31, 57029.54],
                "queue": [4945.77, 5620.61, 5817.89, 5840.01, 5834.71],
                "pdr": [0.98077, 0.98017, 0.98037, 0.98010, 0.98023],
                "cpu": [3.227, 7.188, 10.811, 11.967, 13.622],
                "memory": [7298.4, 15056.2, 22366.3, 28304.2, 33091.2],
            },
            "C": {
                "messages": [71.50, 72.59, 72.07, 70.98, 68.66],
                "bytes": [50333.25, 51101.84, 50736.22, 49970.75, 48334.98],
                "queue": [6306.89, 6543.61, 6590.24, 6577.39, 6553.12],
                "pdr": [0.98046, 0.98003, 0.98021, 0.97994, 0.98003],
                "cpu": [2.092, 4.628, 6.752, 8.123, 9.588],
                "memory": [7412.9, 15445.6, 22905.2, 29069.7, 34048.1],
            },
        },
        "means": {
            "p95": 844.3659, "messages": -10.1378, "bytes": 13811.1462,
            "queue": -902.4536, "cpu": 3.1262, "memory": -553.0159,
        },
    },

    "Grid": {
        "ar": "شبكة الشوارع",
        "meaning": (
            "شبكة طرق متقاطعة متعددة المسارات، وهي القصة التوضيحية الأشمل في "
            "الفصل لأنها تجمع تغير الجوار، وتعدد وحدات الطريق، وV2V وV2I."
        ),
        "workload": {
            "cases": [119.7, 240.5, 365.4, 493.4, 613.2],
            "v2x": [1717.8, 3468.4, 5253.4, 7080.2, 8745.9],
            "detections": [8726.3, 26768.4, 48198.2, 70908.1, 88998.8],
        },
        "classification": {
            "D": {
                "Precision": [0.9045, 0.9200, 0.9104, 0.8893, 0.9110],
                "Recall": [0.6500, 0.8250, 0.7469, 0.7061, 0.6755],
                "FRR": [0.0106, 0.0111, 0.0114, 0.0136, 0.0104],
                "F1": [0.7561, 0.8696, 0.8203, 0.7871, 0.7756],
                "MCC": [0.7383, 0.8527, 0.8009, 0.7651, 0.7571],
            },
            "C": {
                "Precision": [0.9045, 0.9200, 0.9104, 0.8906, 0.9112],
                "Recall": [0.6500, 0.8250, 0.7469, 0.7152, 0.6767],
                "FRR": [0.0106, 0.0111, 0.0114, 0.0136, 0.0104],
                "F1": [0.7561, 0.8696, 0.8203, 0.7932, 0.7764],
                "MCC": [0.7383, 0.8527, 0.8009, 0.7713, 0.7579],
            },
        },
        "p95_d": [14354.97, 14873.79, 15215.49, 15630.80, 15880.65],
        "p95_c200": [14323.50, 14403.48, 14490.78, 14594.70, 14670.70],
        "breakeven": [231.47, 670.31, 924.72, 1236.09, 1409.95],
        "inside": [False, False, False, False, False],
        "ops": {
            "D": {
                "messages": [26.43, 29.21, 28.16, 28.40, 27.68],
                "bytes": [30472.83, 36567.48, 33001.71, 33768.77, 31540.92],
                "queue": [3940.37, 4555.11, 4977.02, 5209.97, 5307.76],
                "pdr": [0.97990, 0.97985, 0.98011, 0.97997, 0.98010],
                "cpu": [1.747, 4.105, 5.745, 8.066, 9.595],
                "memory": [3680.7, 7891.8, 11613.4, 15898.4, 19212.1],
            },
            "C": {
                "messages": [36.36, 38.36, 37.76, 38.10, 37.60],
                "bytes": [25598.10, 27008.06, 26582.14, 26821.31, 26469.52],
                "queue": [5830.35, 6257.68, 6415.50, 6477.11, 6513.75],
                "pdr": [0.98009, 0.97962, 0.97998, 0.98013, 0.98000],
                "cpu": [1.109, 2.345, 3.539, 4.862, 5.939],
                "memory": [3871.2, 8171.0, 12250.3, 16657.9, 20398.0],
            },
        },
        "means": {
            "p95": 694.5073, "messages": -9.6614, "bytes": 6574.5183,
            "queue": -1500.8328, "cpu": 2.2925, "memory": -610.3721,
        },
    },
}

ATTACK_RESULTS = [
    ("الحالة السليمة", "benign", 136, 0.000000, 0.000000,
     "ليست هجوماً؛ وجود 136 حالة ضمن جدول نوع الهجوم لا يجعلها حالات خبيثة."),
    ("العبث بالشهادة", "certificate_tamper", 1211, 1.000000, 1.000000,
     "بوابة صلاحية الشهادة حاسمة، ولذلك تحقق الاستدعاء الكامل في النموذج."),
    ("رسالة حدث لامركزية كاذبة", "false_denm", 1171, 0.557643, 0.549957,
     "يتطلب الكشف تناقض ادعاء الحدث مع التسارع المرصود؛ لذلك يعتمد على وجود ملاحظة فيزيائية كافية."),
    ("الإغراق", "flood", 1090, 0.370642, 0.374312,
     "يُكتشف بعد تجاوز أكثر من ثلاث رسائل في الثانية لدى المراقب؛ تقسيم الاستقبال بين مراقبين قد يخفض التجميع المحلي."),
    ("هجوم مركب", "mixed", 1519, 0.436471, 0.436471,
     "يجمع تزوير الموقع والسرعة والإغراق وDENM؛ عدد الحالات وحده لا يضمن التأهيل لأن القرار يحتاج جذوراً ومصادر مؤهلة."),
    ("إزاحة الموقع", "position_offset", 1155, 0.826840, 0.826840,
     "إزاحة 65 متراً أكبر بوضوح من عتبة خطأ الموقع البالغة 20 متراً، مع بقاء أثر ضوضاء الحساس والتغطية."),
    ("إعادة الإرسال", "replay", 1155, 0.935065, 0.935065,
     "يعتمد على تكرار nonce أو تجاوز عمر 2.5 ثانية، وتملك الأدلة التشفيرية قابلية تحقق مرتفعة."),
    ("إزاحة السرعة", "speed_offset", 1148, 0.777875, 0.777875,
     "زيادة 11 م/ث تتجاوز عتبة عدم اتساق السرعة البالغة 5 م/ث."),
]

CACHE_RESULTS = [
    (0, 0.000, 0.0000, 16.921, 1437.66),
    (1, 39.920, 0.1697, 10.272, 863.04),
    (2, 53.989, 0.3430, 7.941, 662.08),
    (5, 68.805, 0.8412, 5.460, 447.89),
    (10, 75.953, 1.6021, 4.247, 345.25),
    (30, 81.853, 4.9659, 3.289, 260.87),
]

WEIGHTS = {
    "C": 0.3652673861753211,
    "ρ": 0.16195260151983162,
    "F": 0.06370517641034751,
    "Q": 0.40608957775126925,
    "η": 0.0029852581432305157,
}

QUALIFICATION = [
    ("تزوير الموقع", 2, 2, 2, 1, 0.45),
    ("تزوير السرعة", 2, 2, 1, 1, 0.45),
    ("إعادة الإرسال", 1, 1, 1, 1, 0.35),
    ("العبث بالشهادة", 1, 1, 1, 1, 0.25),
    ("الإغراق", 2, 2, 1, 1, 0.50),
    ("DENM كاذبة", 2, 2, 2, 1, 0.50),
    ("الهجوم المركب", 2, 2, 2, 1, 0.55),
]

GLOSSARY = [
    ("V-PUFT", "إطار الثقة المقترح في المشروع", "النظام الذي يزن الأدلة ويؤهلها قبل تغيير حالة الثقة."),
    ("VANET", "شبكة مخصصة للمركبات", "شبكة ديناميكية تتواصل فيها المركبات والبنية التحتية."),
    ("V2X", "اتصال المركبة بكل العناصر", "الاسم الجامع لاتصالات المركبة مع مركبات أو بنية تحتية."),
    ("V2V", "مركبة إلى مركبة", "اتصال مباشر بين مركبتين، ويُستخدم في تحليل مشاركة رمز الثقة والكاش."),
    ("V2I", "مركبة إلى بنية تحتية", "اتصال المركبة بوحدة طريق أو بنية شبكية."),
    ("RSU", "وحدة جانب الطريق", "عقدة ثابتة تستقبل الرسائل وتراقب الحركة وقد تعمل مدققاً أو منسقاً."),
    ("CAM", "رسالة الوعي التعاوني", "رسالة دورية تصف الموقع والسرعة والحركة الحالية للمركبة."),
    ("DENM", "رسالة الإشعار البيئي اللامركزية", "رسالة حدث أو خطر مروري؛ قد يزورها المهاجم."),
    ("SUMO", "محاكي التنقل الحضري", "مولد آثار حركة المركبات المستخدمة في التجربة."),
    ("CRN", "الأعداد العشوائية المشتركة", "اقتران السحوبات العشوائية لتقليل ضجيج المقارنة."),
    ("EvidenceAttestation", "إقرار أو شهادة دليل", "وحدة الدليل التي تحمل الاتجاه والعوامل والهوية الثابتة."),
    ("PBFT", "تحمل الأعطال البيزنطية العملي", "نموذج توافق بين أربعة مدققين مع نصاب ثلاثة."),
    ("f", "عدد العقد البيزنطية المتحملة", "في هذه الحملة f=1، ولذلك النصاب 2f+1=3."),
    ("Backhaul", "الوصلة الخلفية", "الربط بين وحدة الطريق والخادم المركزي البعيد."),
    ("TTL", "مدة صلاحية الإدخال", "الفترة التي يبقى فيها رمز الثقة صالحاً داخل الكاش."),
    ("Cache hit", "إصابة الكاش", "العثور على رمز صالح محلياً من دون استعلام بنية تحتية."),
    ("Cache miss", "إخفاق الكاش", "غياب رمز صالح، ما يفرض استعلام V2I وجمع رمز جديد."),
    ("PDR", "نسبة تسليم الرزم", "عدد الرسائل المسلّمة مقسوماً على عدد الرسائل المرسلة."),
    ("P50", "المئين الخمسون", "الوسيط؛ نصف الأزمنة يقع تحته."),
    ("P95", "المئين الخامس والتسعون", "زمن لا تتجاوزه 95% من القرارات في العينة."),
    ("P99", "المئين التاسع والتسعون", "قراءة أكثر تطرفاً لذيل التأخير."),
    ("TP", "موجب صحيح", "حالة خبيثة أُلغي اعتمادها بصورة صحيحة."),
    ("FP", "موجب كاذب", "حالة سليمة أُلغي اعتمادها خطأً."),
    ("TN", "سالب صحيح", "حالة سليمة لم تُلغَ."),
    ("FN", "سالب كاذب", "حالة خبيثة لم تُلغَ."),
    ("Precision", "دقة قرارات الإلغاء", "من بين الملغاة، كم حالة كانت خبيثة فعلاً."),
    ("Recall", "حساسية الكشف", "من بين الحالات الخبيثة، كم حالة اكتُشفت وأُلغيت."),
    ("FRR", "معدل الرفض الكاذب", "نسبة الحالات السليمة التي أُلغي اعتمادها خطأً."),
    ("F1", "المتوسط التوافقي", "موازنة بين Precision وRecall."),
    ("MCC", "معامل ارتباط ماثيوز", "ملخص متوازن لخانات مصفوفة الالتباس الأربع."),
    ("CPU", "زمن المعالج", "زمن تنفيذ برمجي نسبي داخل بيئة الحملة."),
    ("Peak Memory", "ذروة الذاكرة", "أعلى ذاكرة رُصدت أثناء التشغيل البرمجي."),
    ("Bootstrap CI", "فاصل ثقة بإعادة المعاينة", "تقدير عدم اليقين بإعادة سحب العينات."),
    ("Wilcoxon", "اختبار الرتب الموقعة", "اختبار لافتراضي للفروق المقترنة."),
    ("Holm", "تصحيح هولم", "ضبط الخطأ العائلي عند اختبار عدة فرضيات."),
    ("Macro-average", "متوسط المقاييس", "حساب المقياس لكل بذرة ثم أخذ متوسط البذور."),
    ("Pooled", "تجميع الخانات", "جمع TP وFP وTN وFN أولاً ثم حساب المقياس."),
]

METRICS = [
    (
        "Precision", "TP/(TP+FP)", "دون وحدة؛ الأعلى أفضل",
        "لأن قرار الإلغاء الأمني يجب ألا يستهدف مركبات سليمة بكثرة.",
        "يتغير بتغير TP وFP وتركيب الحالات، وليس بعدد الرسائل وحده."
    ),
    (
        "Recall", "TP/(TP+FN)", "دون وحدة؛ الأعلى أفضل",
        "لقياس نسبة الهجمات التي وصلت فعلياً إلى قرار إلغاء.",
        "يتأثر بالكشف والتغطية ووصول الأدلة والتأهيل والإنهاء المعماري."
    ),
    (
        "FRR", "FP/(FP+TN)", "دون وحدة؛ الأدنى أفضل",
        "لقياس الضرر الواقع على المركبات السليمة.",
        "يجب تفسيره مع Recall لأن رفع الحساسية قد يرفع الرفض الكاذب."
    ),
    (
        "F1", "2×Precision×Recall/(Precision+Recall)", "دون وحدة؛ الأعلى أفضل",
        "لتلخيص التوازن بين صحة الإلغاء واكتشاف الهجمات.",
        "لا يستخدم TN، لذلك لا يغني عن MCC وFRR."
    ),
    (
        "MCC",
        "(TP×TN−FP×FN)/√((TP+FP)(TP+FN)(TN+FP)(TN+FN))",
        "من −1 إلى +1؛ الأعلى أفضل",
        "لأنه أكثر اتزاناً عند عدم توازن أعداد الحالات السليمة والخبيثة.",
        "فرق صغير جداً لا يعني أفضلية عملية تلقائية."
    ),
    (
        "P95 latency", "المئين 95 لأزمنة القرار", "ميلي ثانية؛ الأدنى أفضل",
        "لقياس ذيل التأخير بدلاً من المتوسط فقط.",
        "يتأثر بالتأهيل والطوابير والتوافق والنسخ والوصلة الخلفية."
    ),
    (
        "Messages/Decision", "إجمالي الرسائل/عدد القرارات", "رسالة لكل قرار؛ الأدنى أقل تراسلاً",
        "لقياس عدد عمليات التبادل الشبكي.",
        "لا يساوي حجم المرور؛ رسالة واحدة قد تحمل حزمة أدلة كبيرة."
    ),
    (
        "Bytes/Decision", "إجمالي البايتات/عدد القرارات", "بايت لكل قرار؛ الأدنى أقل حجماً",
        "لقياس الحمل الشبكي الحجمي.",
        "يتأثر بحجم حزم الأدلة وPBFT ونسخ السجل، وليس بعدد الرسائل فقط."
    ),
    (
        "Queue delay", "Σ(تأخير الرسالة×عدد الرسائل)/Σعدد الرسائل",
        "ميلي ثانية؛ الأدنى أفضل",
        "لقياس ضغط الانتظار الذي تختبره الرسالة النموذجية.",
        "يجب وزنه بعدد رسائل كل تشغيلة؛ المتوسط غير الموزون بين الأنواع مضلل."
    ),
    (
        "PDR", "الرسائل المسلّمة/الرسائل المرسلة", "نسبة؛ الأعلى أفضل",
        "للتحقق من أن المقارنة لم تُحسم بانهيار واسع في التسليم.",
        "هو مخرج نموذج النقل البرمجي، لا قياس قناة لاسلكية ميدانية."
    ),
    (
        "CPU time", "زمن المعالج المستهلك في التشغيل", "ثانية؛ الأدنى أخف داخل البيئة",
        "لوصف الكلفة الحسابية النسبية.",
        "يتأثر ببايثون والجهاز والجدولة، ولا يمثل مواصفة RSU إنتاجية."
    ),
    (
        "Peak Memory", "أعلى ذاكرة أثناء التشغيل", "كيلوبايت؛ الأدنى أخف وصفياً",
        "لوصف أثر تخزين الحالات والأدلة.",
        "قياس وصفي حساس لبيئة التنفيذ وليس متطلب عتاد نهائياً."
    ),
]

def fmt(value, digits=4):
    if isinstance(value, int):
        return f"{value:,}"
    if isinstance(value, float):
        return f"{value:,.{digits}f}"
    return escape(str(value))

def rows(items):
    return "".join(
        "<tr>" + "".join(f"<td>{value}</td>" for value in item) + "</tr>"
        for item in items
    )

def table(headers, body, css="prof-table"):
    head = "".join(f"<th>{escape(str(h))}</th>" for h in headers)
    return (
        f'<div class="prof-table-wrap"><table class="{css}">'
        f"<thead><tr>{head}</tr></thead><tbody>{rows(body)}</tbody>"
        "</table></div>"
    )

def card(title, content, cls=""):
    return (
        f'<article class="prof-card {cls}">'
        f"<h3>{title}</h3>{content}</article>"
    )

def ratio(first, last):
    return last / first if first else 0.0

def architecture_diff(data, metric, index):
    return data["classification"]["D"][metric][index] - data["classification"]["C"][metric][index]

def svg_box(x, y, w, h, title, subtitle="", color="#0f766e"):
    return f"""
    <g>
      <rect x="{x}" y="{y}" width="{w}" height="{h}" rx="16"
            fill="white" stroke="{color}" stroke-width="3"/>
      <text x="{x+w/2}" y="{y+31}" text-anchor="middle"
            class="svg-title">{escape(title)}</text>
      <text x="{x+w/2}" y="{y+56}" text-anchor="middle"
            class="svg-sub">{escape(subtitle)}</text>
    </g>
    """

def arrow(x1, y1, x2, y2, label=""):
    return f"""
    <line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}"
          stroke="#475569" stroke-width="3"
          marker-end="url(#prof-arrow)"/>
    <text x="{(x1+x2)/2}" y="{(y1+y2)/2-8}"
          text-anchor="middle" class="svg-label">{escape(label)}</text>
    """

def svg_wrap(title, inner, height=380):
    return f"""
    <figure class="prof-diagram">
      <svg viewBox="0 0 1200 {height}" role="img"
           aria-label="{escape(title)}">
        <defs>
          <marker id="prof-arrow" markerWidth="10" markerHeight="10"
                  refX="8" refY="3" orient="auto">
            <path d="M0,0 L0,6 L9,3 z" fill="#475569"/>
          </marker>
        </defs>
        <style>
          .svg-title{{font:700 18px Arial;fill:#0f172a}}
          .svg-sub{{font:14px Arial;fill:#475569}}
          .svg-label{{font:700 14px Arial;fill:#334155}}
        </style>
        {inner}
      </svg>
      <figcaption>{escape(title)}</figcaption>
    </figure>
    """

def classification_table(data):
    body = []
    for i, n in enumerate(VEHICLES):
        for arch, ar in (("D", "الموزع"), ("C", "المركزي المتاح دائماً")):
            m = data["classification"][arch]
            body.append((
                n, ar,
                fmt(m["Precision"][i]),
                fmt(m["Recall"][i]),
                fmt(m["FRR"][i]),
                fmt(m["F1"][i]),
                fmt(m["MCC"][i]),
            ))
    return table(
        ["المركبات", "البنية", "Precision", "Recall", "FRR", "F1", "MCC"],
        body
    )

def workload_table(data):
    return table(
        ["المركبات الاسمية", "الحالات", "رسائل V2X", "أحداث الكشف"],
        [
            (
                VEHICLES[i],
                fmt(data["workload"]["cases"][i], 1),
                fmt(data["workload"]["v2x"][i], 1),
                fmt(data["workload"]["detections"][i], 1),
            )
            for i in range(5)
        ]
    )

def latency_table(data):
    return table(
        [
            "المركبات", "P95 الموزع", "P95 المركزي +200 ms",
            "نقطة التعادل", "حالة النقطة"
        ],
        [
            (
                VEHICLES[i],
                fmt(data["p95_d"][i], 2),
                fmt(data["p95_c200"][i], 2),
                fmt(data["breakeven"][i], 2),
                "داخل 0–200 ms" if data["inside"][i]
                else "استقراء نموذجي خارج المجال",
            )
            for i in range(5)
        ]
    )

def operations_table(data):
    body = []
    for i, n in enumerate(VEHICLES):
        for arch, ar in (("D", "الموزع"), ("C", "المركزي")):
            o = data["ops"][arch]
            body.append((
                n, ar,
                fmt(o["messages"][i], 2),
                fmt(o["bytes"][i], 2),
                fmt(o["queue"][i], 2),
                fmt(o["pdr"][i], 5),
                fmt(o["cpu"][i], 3),
                fmt(o["memory"][i], 1),
            ))
    return table(
        [
            "المركبات", "البنية", "رسائل/قرار", "بايت/قرار",
            "Queue ms", "PDR", "CPU s", "Memory KB"
        ],
        body
    )

def topology_analysis(name, data):
    work = data["workload"]
    d = data["classification"]["D"]
    c = data["classification"]["C"]
    ops_d = data["ops"]["D"]
    ops_c = data["ops"]["C"]

    case_growth = ratio(work["cases"][0], work["cases"][-1])
    v2x_growth = ratio(work["v2x"][0], work["v2x"][-1])
    det_growth = ratio(work["detections"][0], work["detections"][-1])

    max_recall_i = max(range(5), key=lambda i: d["Recall"][i])
    min_recall_i = min(range(5), key=lambda i: d["Recall"][i])
    max_mcc_i = max(range(5), key=lambda i: d["MCC"][i])

    unequal = []
    for metric in ("Precision", "Recall", "FRR", "F1", "MCC"):
        for i, n in enumerate(VEHICLES):
            delta = d[metric][i] - c[metric][i]
            if abs(delta) > 0.00005:
                unequal.append(f"{metric} عند {n}: Δ={delta:+.4f}")

    unequal_text = (
        "؛ ".join(unequal)
        if unequal
        else "لم يظهر فرق معروض بين البنيتين في أي كثافة ضمن الدقة المنشورة."
    )

    byte_patterns = []
    for i, n in enumerate(VEHICLES):
        delta = ops_d["bytes"][i] - ops_c["bytes"][i]
        side = "أكثر" if delta > 0 else "أقل"
        byte_patterns.append(f"{n}: الموزع {side} بـ{abs(delta):,.2f} B/قرار")

    inside = [
        f"{VEHICLES[i]} مركبة: {data['breakeven'][i]:.2f} ms"
        for i in range(5) if data["inside"][i]
    ]

    inside_text = (
        "، ".join(inside)
        if inside
        else "لا توجد نقطة داخل مجال 0–200 ms."
    )

    return f"""
    <section class="prof-topology" id="prof-{name.lower()}">
      <h2>{escape(name)} — {data["ar"]}</h2>
      <p class="prof-lead">{data["meaning"]}</p>

      <h3>أولاً: حجم العمل الحقيقي</h3>
      {workload_table(data)}
      <div class="prof-analysis">
        <p>
          رفع العدد الاسمي من 20 إلى 100 لم يضرب جميع المخرجات في خمسة:
          الحالات زادت بنحو <strong>{case_growth:.2f}×</strong>،
          ورسائل V2X بنحو <strong>{v2x_growth:.2f}×</strong>،
          وأحداث الكشف بنحو <strong>{det_growth:.2f}×</strong>.
          السبب أن العدد الاسمي ليس مقام كل مقياس: المركبات تدخل خلال نافذة
          مغادرة، وتختلف مدة بقائها والتغطية والجوار وعدد المراقبين والرسائل
          المتولدة لكل حالة.
        </p>
        <p>
          لذلك لا يجوز تفسير أي منحنى بالقول «زاد عدد المركبات فقط».
          السلسلة الفعلية هي: مركبات نشطة ← رسائل V2X ← فرص مراقبة ←
          أحداث كشف ← أدلة مؤهلة ← قرارات.
        </p>
      </div>

      <h3>ثانياً: مقاييس التصنيف حسب الكثافة</h3>
      {classification_table(data)}
      <div class="prof-analysis">
        <p>
          أعلى Recall للموزع ظهر عند <strong>{VEHICLES[max_recall_i]}</strong>
          مركبة بقيمة <strong>{d["Recall"][max_recall_i]:.4f}</strong>،
          وأدناه عند <strong>{VEHICLES[min_recall_i]}</strong> مركبة بقيمة
          <strong>{d["Recall"][min_recall_i]:.4f}</strong>.
          أعلى MCC ظهر عند <strong>{VEHICLES[max_mcc_i]}</strong> مركبة بقيمة
          <strong>{d["MCC"][max_mcc_i]:.4f}</strong>.
        </p>
        <p>
          هذه الحركة غير الرتيبة دليل على أن التصنيف لا تحدده الكثافة وحدها؛
          تتغير معها الحالات المتاحة، وعدد جذور الملاحظة المستقلة، وتوزع
          أنواع الهجوم والتغطية والتوقيت. التفسير السببي الوحيد المعزول بين
          البنيتين يأتي من مسار نقل الدليل والإنهاء، لا من شكل الطريق وحده.
        </p>
        <p><strong>الفروق المنشورة:</strong> {unequal_text}</p>
        <p>
          قيم هذه الطبولوجيا Macro-average لمقاييس البذور العشر، بينما
          النتيجة المجمعة Pooled تُحسب بعد جمع خانات مصفوفة الالتباس.
          اختلافهما طبيعي ولا يعني تعارضاً حسابياً.
        </p>
      </div>

      <h3>ثالثاً: التأخير ونقطة التعادل</h3>
      {latency_table(data)}
      <div class="prof-analysis">
        <p>
          متوسط الفرق المعروض D−C عند مستوى المقارنة الخاص بالجدول بلغ
          <strong>{data["means"]["p95"]:+,.4f} ms</strong>.
          الموزع يدفع كلفة إعادة التأهيل والتوافق والنسخ محلياً، بينما
          المركزي البعيد يضيف كلفة Backhaul. نقطة التعادل هي مقدار الوصلة
          الخلفية الذي يجعل P95 المركزي مساوياً لـP95 الموزع في الخلية نفسها.
        </p>
        <p><strong>داخل المجال المختبر:</strong> {inside_text}</p>
        <p>
          أي نقطة تتجاوز 200 ms لا تُعرض كقياس مجرّب؛ بل كاستقراء خطي
          مشروط بقاعدة الإضافة في النموذج.
        </p>
      </div>

      <h3>رابعاً: الاتصال والطابور والموارد</h3>
      {operations_table(data)}
      <div class="prof-analysis">
        <p>
          متوسط D−C في عدد الرسائل لكل قرار =
          <strong>{data["means"]["messages"]:+.4f}</strong>،
          وفي البايتات لكل قرار =
          <strong>{data["means"]["bytes"]:+,.4f}</strong>،
          وفي Queue =
          <strong>{data["means"]["queue"]:+,.4f} ms</strong>.
          هذا يثبت أن عدد الرسائل وحجمها مقياسان مختلفان.
        </p>
        <p>{"؛ ".join(byte_patterns)}.</p>
        <p>
          زمن CPU أعلى في الموزع وصفياً بمتوسط
          <strong>{data["means"]["cpu"]:+.4f} s</strong>،
          لأن كل مدقق يعيد التأهيل وتوجد معالجة توافق ونسخ.
          الذاكرة القصوى أقل وصفياً بمتوسط
          <strong>{data["means"]["memory"]:+,.4f} KB</strong>،
          لكن القياسين يخصان بيئة تنفيذ الحملة ولا يتحولان إلى مواصفات
          عتاد إنتاجي.
        </p>
      </div>
    </section>
    """

print("PART 1 SAVED: data and rendering engine are ready.")

# ============================================================
# PART 2 — PROFESSORIAL DEFENSE DOCUMENT
# ============================================================

import math

CSS = r"""
<style id="prof-defense-style">
:root{
  --prof-navy:#0f172a;
  --prof-blue:#1d4ed8;
  --prof-cyan:#0891b2;
  --prof-green:#0f766e;
  --prof-red:#b91c1c;
  --prof-amber:#b45309;
  --prof-soft:#f8fafc;
  --prof-line:#cbd5e1;
}
.prof-document{
  direction:rtl;
  font-family:"Segoe UI",Tahoma,Arial,sans-serif;
  color:var(--prof-navy);
  line-height:1.9;
  max-width:1500px;
  margin:auto;
}
.prof-cover{
  min-height:88vh;
  display:flex;
  flex-direction:column;
  justify-content:center;
  padding:70px 8%;
  color:white;
  background:
    radial-gradient(circle at 15% 20%,rgba(34,211,238,.22),transparent 30%),
    radial-gradient(circle at 85% 75%,rgba(45,212,191,.18),transparent 32%),
    linear-gradient(135deg,#071225,#0f2747 50%,#0f4c5c);
  border-radius:0 0 34px 34px;
}
.prof-cover h1{font-size:clamp(2.2rem,5vw,4.6rem);line-height:1.25;margin:0 0 24px}
.prof-cover h2{font-size:clamp(1.2rem,2.3vw,2rem);color:#a5f3fc;margin:0 0 25px}
.prof-cover p{max-width:1100px;font-size:1.15rem}
.prof-badges{display:flex;flex-wrap:wrap;gap:10px;margin-top:25px}
.prof-badge{
  padding:8px 15px;border:1px solid rgba(255,255,255,.35);
  border-radius:999px;background:rgba(255,255,255,.09)
}
.prof-main{padding:30px 4% 80px}
.prof-section,.prof-topology{
  margin:38px 0;padding:34px;
  background:white;border:1px solid #dbeafe;border-radius:22px;
  box-shadow:0 12px 35px rgba(15,23,42,.07);
}
.prof-section>h2,.prof-topology>h2{
  margin-top:0;color:#0f4c5c;font-size:2rem;
  border-right:7px solid #14b8a6;padding-right:15px
}
.prof-section h3,.prof-topology h3{color:#1e3a8a;margin-top:30px}
.prof-lead{font-size:1.13rem;background:#ecfeff;border-right:5px solid #0891b2;padding:18px}
.prof-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(270px,1fr));gap:18px}
.prof-card{
  border:1px solid #dbeafe;border-radius:18px;padding:20px;
  background:linear-gradient(180deg,#fff,#f8fafc)
}
.prof-card h3{margin-top:0;color:#0f766e}
.prof-analysis{
  background:#f8fafc;border:1px solid #cbd5e1;
  border-radius:16px;padding:18px 22px;margin:18px 0
}
.prof-warning{background:#fff7ed;border-right:6px solid #ea580c;padding:18px;border-radius:12px}
.prof-ok{background:#ecfdf5;border-right:6px solid #059669;padding:18px;border-radius:12px}
.prof-limit{background:#fef2f2;border-right:6px solid #dc2626;padding:18px;border-radius:12px}
.prof-equation{
  direction:ltr;text-align:center;font-family:Cambria,serif;font-size:1.25rem;
  background:#eff6ff;border:1px solid #93c5fd;border-radius:14px;
  padding:18px;margin:18px 0;overflow:auto
}
.prof-table-wrap{overflow:auto;margin:18px 0;border-radius:14px;border:1px solid #cbd5e1}
.prof-table{width:100%;border-collapse:collapse;background:white;font-size:.94rem}
.prof-table th{background:#0f4c5c;color:white;padding:12px;white-space:nowrap}
.prof-table td{border-top:1px solid #e2e8f0;padding:10px;vertical-align:top}
.prof-table tr:nth-child(even){background:#f8fafc}
.prof-diagram{
  margin:25px 0;padding:18px;background:#f8fafc;
  border:1px solid #cbd5e1;border-radius:20px;overflow:auto
}
.prof-diagram svg{display:block;width:100%;min-width:780px;height:auto}
.prof-diagram figcaption{text-align:center;font-weight:700;color:#334155;margin-top:10px}
.prof-toc{columns:2;column-gap:35px}
.prof-toc li{break-inside:avoid;margin:7px 0}
.prof-toc a{color:#1d4ed8;text-decoration:none}
.prof-source{font-family:Consolas,monospace;direction:ltr;text-align:left;font-size:.88rem}
.prof-old-report{
  margin:45px 3%;border:3px solid #0f766e;border-radius:22px;
  background:white;padding:20px
}
.prof-old-report>summary{
  cursor:pointer;font-size:1.5rem;font-weight:800;color:#0f4c5c;padding:15px
}
.prof-footnote{font-size:.9rem;color:#475569}
@media(max-width:800px){
  .prof-main{padding:15px}
  .prof-section,.prof-topology{padding:20px}
  .prof-toc{columns:1}
}
@media print{
  .prof-cover{min-height:auto;page-break-after:always}
  .prof-section,.prof-topology{box-shadow:none;break-inside:avoid-page}
  .prof-old-report>summary{display:none}
}
</style>
"""

grid_svg = svg_wrap(
    "المخطط 1 — شبكة الشوارع Grid بوصفها القصة التوضيحية الأشمل",
    """
    <rect x="60" y="60" width="1080" height="260" rx="22"
          fill="#e0f2fe" stroke="#0369a1" stroke-width="3"/>
    <path d="M120 150 H1080 M120 245 H1080 M330 85 V295 M610 85 V295 M890 85 V295"
          stroke="#64748b" stroke-width="38"/>
    <path d="M120 150 H1080 M120 245 H1080 M330 85 V295 M610 85 V295 M890 85 V295"
          stroke="white" stroke-width="3" stroke-dasharray="18 14"/>
    <circle cx="330" cy="150" r="24" fill="#0f766e"/>
    <circle cx="610" cy="245" r="24" fill="#0f766e"/>
    <circle cx="890" cy="150" r="24" fill="#0f766e"/>
    <text x="330" y="157" text-anchor="middle" fill="white" font-weight="bold">RSU</text>
    <text x="610" y="252" text-anchor="middle" fill="white" font-weight="bold">RSU</text>
    <text x="890" y="157" text-anchor="middle" fill="white" font-weight="bold">RSU</text>
    <rect x="205" y="127" width="62" height="32" rx="8" fill="#2563eb"/>
    <rect x="480" y="222" width="62" height="32" rx="8" fill="#dc2626"/>
    <rect x="735" y="127" width="62" height="32" rx="8" fill="#2563eb"/>
    <text x="236" y="119" text-anchor="middle" class="svg-label">مركبة سليمة</text>
    <text x="511" y="214" text-anchor="middle" class="svg-label">مركبة خبيثة</text>
    <text x="766" y="119" text-anchor="middle" class="svg-label">مركبة شاهدة</text>
    <text x="600" y="350" text-anchor="middle" class="svg-sub">
      الخطوط تمثل طرقاً مجردة للتفسير وليست خريطة ميدانية أو نموذج قناة راديوية حقيقية
    </text>
    """,
    380
)

scenario_svg = svg_wrap(
    "المخطط 2 — الرحلة الكاملة من رسالة المركبة إلى قرار الثقة",
    svg_box(30,110,205,90,"المركبة","CAM أو DENM") +
    arrow(235,155,290,155,"V2X") +
    svg_box(290,110,205,90,"المراقب","RSU أو شاهد V2V") +
    arrow(495,155,550,155,"ملاحظة حسية") +
    svg_box(550,110,205,90,"الكاشف","أسباب واتجاه دليل") +
    arrow(755,155,810,155,"Attestation") +
    svg_box(810,110,170,90,"التأهيل","جذور ومصادر") +
    arrow(980,155,1030,155,"قرار") +
    svg_box(1030,110,145,90,"الثقة","إلغاء/إبقاء") +
    """
    <text x="600" y="265" text-anchor="middle" class="svg-sub">
      الحقيقة الأرضية لا تدخل الكاشف؛ تُستخدم لاحقاً فقط لحساب TP وFP وTN وFN
    </text>
    """,
    310
)

detection_svg = svg_wrap(
    "المخطط 3 — كشف الهجمات دون تسرب الحقيقة الأرضية",
    svg_box(30,45,230,80,"الرسالة المبلّغ عنها","موقع، سرعة، nonce، شهادة") +
    svg_box(30,185,230,80,"الملاحظة الحسية","قيم مشوشة عند الاستقبال") +
    arrow(260,85,430,130,"") +
    arrow(260,225,430,170,"") +
    svg_box(430,105,270,100,"قواعد الكشف",
            "20 m | 5 m/s | 2.5 s | >3 msg/s") +
    arrow(700,155,800,155,"Reason codes") +
    svg_box(800,105,350,100,"دليل موقّع","تأييد أو معارضة + خمسة عوامل") +
    """
    <rect x="420" y="265" width="300" height="70" rx="15"
          fill="#fef2f2" stroke="#dc2626" stroke-width="3"/>
    <text x="570" y="294" text-anchor="middle" class="svg-title">Ground Truth</text>
    <text x="570" y="319" text-anchor="middle" class="svg-sub">للتقييم فقط — لا سهم نحو الكاشف</text>
    """,
    370
)

weight_svg = svg_wrap(
    "المخطط 4 — من عوامل الدليل إلى كتلة التأييد أو المعارضة",
    svg_box(20,105,170,90,"العوامل","C, ρ, F, Q, η") +
    arrow(190,150,260,150,"أسس مجمدة") +
    svg_box(260,105,205,90,"وزن الدليل","متوسط هندسي موزون") +
    arrow(465,150,535,150,"تجميع الجذر") +
    svg_box(535,105,210,90,"منع التكرار","أقوى تأييد − معارضة") +
    arrow(745,150,815,150,"−ln(1−w)") +
    svg_box(815,105,170,90,"كتل الأدلة","M+ و M−") +
    arrow(985,150,1040,150,"عتبة") +
    svg_box(1040,105,140,90,"التأهيل","قرار مشروط"),
    310
)

architecture_svg = svg_wrap(
    "المخطط 5 — أين تختلف المعماريتان فعلياً؟",
    """
    <text x="30" y="75" class="svg-title">المركزي البعيد</text>
    """ +
    svg_box(170,35,170,80,"RSU","ترسل كل دليل") +
    arrow(340,75,430,75,"Backhaul") +
    svg_box(430,35,210,80,"الخادم المركزي","4 عمال، 12 ms، Queue") +
    arrow(640,75,730,75,"تأهيل") +
    svg_box(730,35,190,80,"قرار مركزي","سجل + نسخة تدقيق") +
    """
    <text x="30" y="225" class="svg-title">الموزّع</text>
    """ +
    svg_box(170,185,170,80,"المنسق","دليله محلي") +
    arrow(340,225,430,225,"حزمة أدلة") +
    svg_box(430,185,210,80,"4 مدققين","إعادة تأهيل مستقلة") +
    arrow(640,225,730,225,"نصاب 3/4") +
    svg_box(730,185,190,80,"PBFT","اتفاق ونسخ") +
    arrow(920,225,1005,225,"") +
    svg_box(1005,185,170,80,"السجل","مدققون + 6 RSU"),
    330
)

crn_svg = svg_wrap(
    "المخطط 6 — اقتران CRN وعزل الرسائل المعمارية",
    svg_box(35,105,220,90,"EvidenceAttestation","مفتاح دليل ثابت") +
    arrow(255,150,350,150,"SHA-256") +
    svg_box(350,105,260,90,"evidence_crn_seed | key | attempt","مولد خاص بالدليل") +
    arrow(610,150,710,95,"نفس السحب") +
    arrow(610,150,710,205,"نفس السحب") +
    svg_box(710,50,205,85,"المركزي","loss/jitter/retry") +
    svg_box(710,175,205,85,"الموزّع","loss/jitter/retry") +
    """
    <rect x="960" y="105" width="210" height="90" rx="16"
          fill="#fff7ed" stroke="#ea580c" stroke-width="3"/>
    <text x="1065" y="137" text-anchor="middle" class="svg-title">PBFT والكاش</text>
    <text x="1065" y="165" text-anchor="middle" class="svg-sub">تيار مستقل لا يزحزح</text>
    <text x="1065" y="186" text-anchor="middle" class="svg-sub">سحب الدليل التالي</text>
    """,
    320
)

cache_svg = svg_wrap(
    "المخطط 7 — دورة Trust Cache بين الإصابة والإخفاق والإبطال",
    svg_box(30,105,180,90,"طلب تفويض","مركبة أو جار V2V") +
    arrow(210,150,290,150,"بحث") +
    svg_box(290,105,180,90,"الكاش المحلي","فحص TTL والتواقيع") +
    arrow(470,150,555,75,"Hit: 0.25 ms") +
    svg_box(555,35,210,85,"رمز صالح","تفويض محلي") +
    arrow(470,150,555,225,"Miss/Expiry") +
    svg_box(555,185,210,85,"استعلام V2I","256 B طلب") +
    arrow(765,227,850,227,"") +
    svg_box(850,185,210,85,"RSU","1152 B استجابة") +
    arrow(1060,227,1160,150,"رمز نصاب") +
    """
    <path d="M1060 75 C1120 75 1145 95 1160 130"
          stroke="#0f766e" stroke-width="3" fill="none"
          marker-end="url(#prof-arrow)"/>
    <text x="890" y="70" class="svg-label">Anomaly أو Revocation يبطل الكاش</text>
    """,
    330
)

causal_svg = svg_wrap(
    "المخطط 8 — خريطة العوامل التي تولّد القيم التشغيلية",
    svg_box(25,105,175,90,"مركبات نشطة","ليس العدد الاسمي فقط") +
    arrow(200,150,260,150,"") +
    svg_box(260,105,175,90,"رسائل V2X","CAM/DENM/Flood") +
    arrow(435,150,495,150,"") +
    svg_box(495,105,175,90,"أحداث كشف","مراقبون وتغطية") +
    arrow(670,150,730,150,"") +
    svg_box(730,105,175,90,"أدلة مؤهلة","جذور ومصادر") +
    arrow(905,150,965,150,"") +
    svg_box(965,105,210,90,"الكلفة النهائية","Queue/Bytes/CPU/P95") +
    """
    <text x="600" y="260" text-anchor="middle" class="svg-sub">
      لا توجد دالة من «عدد المركبات» وحده إلى النتيجة؛ توجد سلسلة وسائط متداخلة
    </text>
    """,
    310
)

glossary_html = table(
    ["الرمز أو المصطلح", "الترجمة العربية", "ماذا يمثل في هذا الفصل؟"],
    [(f"<code>{escape(term)}</code>", ar, meaning) for term, ar, meaning in GLOSSARY]
)

metric_html = table(
    ["المعيار", "الحساب", "الوحدة واتجاه الأفضلية", "لماذا اختير؟", "محددات تفسيره"],
    [
        (
            f"<code>{escape(name)}</code>",
            f"<span dir='ltr'>{escape(formula)}</span>",
            direction,
            why,
            drivers,
        )
        for name, formula, direction, why, drivers in METRICS
    ]
)

attack_html = table(
    [
        "الحالة", "رمز الكود", "عدد الحالات", "Recall المركزي",
        "Recall الموزع", "الفرق D−C", "لماذا ظهرت النتيجة؟"
    ],
    [
        (
            ar, f"<code>{code}</code>", f"{count:,}",
            f"{rc:.6f}", f"{rd:.6f}", f"{rd-rc:+.6f}", why
        )
        for ar, code, count, rc, rd, why in ATTACK_RESULTS
    ]
)

qualification_html = table(
    ["نوع الهجوم", "الجذور", "المصادر", "المناطق", "الوسائط", "عتبة القوة"],
    [
        (name, roots, sources, zones, modalities, f"{threshold:.2f}")
        for name, roots, sources, zones, modalities, threshold in QUALIFICATION
    ]
)

cache_html = table(
    [
        "TTL بالثواني", "إصابة الكاش", "قبول ثقة قديمة",
        "متوسط التفويض ms", "بايت/تفاعل"
    ],
    [
        (
            ttl, f"{hit:.3f}%", f"{stale:.4f}%",
            f"{latency:.3f}", f"{byte_count:,.2f}"
        )
        for ttl, hit, stale, latency, byte_count in CACHE_RESULTS
    ]
)

weights_example_factors = {
    "C": 0.90, "ρ": 0.85, "F": 0.95, "Q": 0.98, "η": 0.92
}
weights_example = math.exp(sum(
    WEIGHTS[key] * math.log(weights_example_factors[key])
    for key in WEIGHTS
))

weights_html = table(
    ["الرمز", "المعنى", "الأس المجمد", "قراءة علمية"],
    [
        ("C", "ثقة الكاشف", f"{WEIGHTS['C']:.6f}", "مدى قوة التناقض المرصود."),
        ("ρ", "موثوقية المصدر", f"{WEIGHTS['ρ']:.6f}", "تاريخ أو موثوقية RSU/الشاهد."),
        ("F", "حداثة الدليل", f"{WEIGHTS['F']:.6f}", "تنخفض أسياً مع عمر الدليل."),
        ("Q", "قابلية التحقق", f"{WEIGHTS['Q']:.6f}", "أكبر أس؛ الأدلة التشفيرية أكثر قابلية للتحقق."),
        ("η", "الاستقلالية", f"{WEIGHTS['η']:.6f}", "عامل مساعد؛ منع التكرار الجذري مستقل عنه."),
        ("V", "بوابة الصلاحية", "0 أو 1", "إذا كانت الشهادة غير صالحة يصبح الوزن صفراً."),
    ]
)

topology_cards = "".join(
    card(
        f"{name} — {data['ar']}",
        f"<p>{data['meaning']}</p>"
    )
    for name, data in TOPOLOGIES.items()
)

topology_sections = "".join(
    topology_analysis(name, data)
    for name, data in TOPOLOGIES.items()
)

overall_topology_table = table(
    [
        "الطبولوجيا", "Recall موزع", "FRR موزع", "MCC موزع",
        "P95 موزع", "P95 مركزي +200", "رسائل/قرار", "بايت/قرار"
    ],
    [
        ("Smoke", "0.5379", "0.0086", "0.6585", "14,487.39", "14,474.73", "22.22", "21,212.43"),
        ("Corridor", "0.7206", "0.0092", "0.7902", "15,042.69", "14,554.54", "31.82", "34,094.37"),
        ("Intersection", "0.7140", "0.0104", "0.7824", "15,477.47", "14,633.11", "61.02", "63,906.55"),
        ("Grid", "0.7207", "0.0114", "0.7828", "15,191.14", "14,496.63", "27.97", "33,070.34"),
    ]
)

traceability_html = table(
    ["النتيجة أو الرقم", "مصدر البيانات", "الملف/الدالة البرمجية", "ما الذي يثبته؟"],
    [
        (
            "20–100 مركبة و35% مهاجمين",
            "density_scenario_manifest.json وattacks.json",
            "<code>src/vpuft/sumo/density.py :: build_density_scenario</code>",
            "توليد الطلب وتوزيع المركبات الهجومية بالتباعد ودورة الهجمات."
        ),
        (
            "إزاحة الموقع والسرعة والإعادة والإغراق",
            "attacks.json والرسائل المولدة",
            "<code>src/vpuft/sumo/attacks.py :: AttackInjector.generate</code>",
            "كيفية حقن السلوك الخبيث داخل الرسالة."
        ),
        (
            "أسباب الكشف والعوامل الخمسة",
            "DetectionEvent وreason_codes",
            "<code>src/vpuft/sumo/detector.py :: _reason_codes, _factors</code>",
            "أن الكاشف Label-blind ويستخدم ملاحظة حسية."
        ),
        (
            "وزن الدليل ومنع التكرار",
            "EvidenceAttestation",
            "<code>src/vpuft/weighting.py :: evidence_weight, aggregate_by_root</code>",
            "حساب الوزن والتجميع على مستوى جذر الملاحظة."
        ),
        (
            "الخادم والطابور والإتاحة",
            "نتائج central_crn_*",
            "<code>src/vpuft/architectures/centralized.py</code>",
            "المسار المركزي ونقطة عدم الإتاحة."
        ),
        (
            "النصاب والتوافق والنسخ",
            "نتائج distributed_crn_honest",
            "<code>src/vpuft/architectures/distributed_extension.py</code>",
            "إعادة التأهيل وPBFT والنسخ في الموزع."
        ),
        (
            "اقتران loss/jitter/retry",
            "معرف EvidenceAttestation",
            "<code>src/vpuft/network.py</code>",
            "اشتقاق السحب من المفتاح والمحاولة بدلاً من ترتيب الرسائل."
        ),
        (
            "TP/FP/TN/FN و17/51",
            "<code>paired_decisions.csv</code>",
            "أعمدة الحقيقة والقرار والمقارن والسبب",
            "إعادة حساب التصنيف والاختلافات على مستوى الحالة."
        ),
        (
            "P95 وBackhaul ونقاط التعادل",
            "ملفات paired transport والـbreakeven",
            "سكربت تحليل Evidence-CRN",
            "اشتقاق الزمن وفصل المجال المختبر عن الاستقراء."
        ),
        (
            "TTL وإصابة الكاش وقبول القديم",
            "نتائج TTL sweep",
            "<code>src/vpuft/trust_cache.py</code>",
            "مقايضة السرعة والاتصال مقابل حداثة الثقة."
        ),
    ]
)

references_html = """
<ol>
  <li>
    Eclipse SUMO، وثائق محاكي التنقل الحضري:
    <a href="https://sumo.dlr.de/docs/">https://sumo.dlr.de/docs/</a>.
  </li>
  <li>
    ETSI EN 302 637-2، خدمة رسائل الوعي التعاوني CAM:
    <a href="https://www.etsi.org/deliver/etsi_en/302600_302699/30263702/01.04.01_60/en_30263702v010401p.pdf">
      المعيار الرسمي
    </a>.
  </li>
  <li>
    ETSI EN 302 637-3، خدمة رسائل DENM:
    <a href="https://www.etsi.org/deliver/etsi_en/302600_302699/30263703/01.03.01_60/en_30263703v010301p.pdf">
      المعيار الرسمي
    </a>.
  </li>
  <li>
    Castro and Liskov، Practical Byzantine Fault Tolerance:
    <a href="https://www.usenix.org/conference/osdi-99/practical-byzantine-fault-tolerance">
      USENIX OSDI 1999
    </a>.
  </li>
  <li>
    Holm، A Simple Sequentially Rejective Multiple Test Procedure:
    <a href="https://doi.org/10.2307/4615733">DOI: 10.2307/4615733</a>.
  </li>
  <li>
    Wilcoxon، Individual Comparisons by Ranking Methods:
    <a href="https://doi.org/10.2307/3001968">DOI: 10.2307/3001968</a>.
  </li>
  <li>
    الشفرة المرجعية للحملة عند commit
    <code>db3b91a814338aa9319ed50c905b4c000d84c466</code>:
    <a href="https://github.com/reemgeorges/V-PUFT/tree/db3b91a814338aa9319ed50c905b4c000d84c466">
      مستودع V-PUFT
    </a>.
  </li>
</ol>
"""

deep_html = f"""
<div class="prof-document" id="prof-defense-document">

<header class="prof-cover">
  <h1>الفصل الخامس الدفاعي الشامل</h1>
  <h2>من قصة المركبة الخبيثة إلى تفسير كل معيار في V-PUFT</h2>
  <p>
    وثيقة تفسيرية مستقلة تربط الشفرة، وتصميم التجربة، والبروتوكولات،
    والأوزان، والهجمات، ومخرجات الكثافة والطبولوجيا، ثم تفصل ما تدعمه
    النتائج عما لا يجوز استنتاجه.
  </p>
  <div class="prof-badges">
    <span class="prof-badge">4 طبولوجيات</span>
    <span class="prof-badge">5 كثافات</span>
    <span class="prof-badge">10 بذور</span>
    <span class="prof-badge">200 أثر SUMO</span>
    <span class="prof-badge">600 تشغيل معماري</span>
    <span class="prof-badge">70,791 حالة مشتركة</span>
    <span class="prof-badge">Post-hoc Supplementary/Exploratory</span>
  </div>
</header>

<main class="prof-main">

<section class="prof-section" id="prof-toc">
  <h2>خريطة القراءة</h2>
  <ol class="prof-toc">
    <li><a href="#prof-glossary">المصطلحات والرموز</a></li>
    <li><a href="#prof-story">قصة السيناريو</a></li>
    <li><a href="#prof-threat">نموذج التهديد والهجمات</a></li>
    <li><a href="#prof-detection">الكشف دون تسرب الحقيقة</a></li>
    <li><a href="#prof-weighting">الأوزان والتأهيل والحساسية</a></li>
    <li><a href="#prof-protocols">البروتوكول المركزي والموزع</a></li>
    <li><a href="#prof-crn">عدالة CRN</a></li>
    <li><a href="#prof-design">تصميم التجربة والمقامات</a></li>
    <li><a href="#prof-metrics">كل معيار ومعادلته</a></li>
    <li><a href="#prof-smoke">تحليل Smoke</a></li>
    <li><a href="#prof-corridor">تحليل Corridor</a></li>
    <li><a href="#prof-intersection">تحليل Intersection</a></li>
    <li><a href="#prof-grid">تحليل Grid</a></li>
    <li><a href="#prof-comparison">المقارنة الجامعة</a></li>
    <li><a href="#prof-cases">تفسير 17 و34 حالة</a></li>
    <li><a href="#prof-cache">V2V والكاش وTTL</a></li>
    <li><a href="#prof-statistics">الاستدلال الإحصائي</a></li>
    <li><a href="#prof-novelty">المساهمة والدراسات السابقة</a></li>
    <li><a href="#prof-traceability">تتبّع كل رقم إلى مصدره</a></li>
    <li><a href="#prof-claims">الادعاءات والقيود</a></li>
  </ol>
</section>

<section class="prof-section" id="prof-glossary">
  <h2>1. قاموس المصطلحات والرموز</h2>
  <p class="prof-lead">
    يُعرّف المصطلح بالعربية عند أول ظهور، ثم يُحتفظ بالاختصار الإنجليزي
    لأنه الاسم المستخدم في الشفرة وملفات النتائج.
  </p>
  {glossary_html}
</section>

<section class="prof-section" id="prof-story">
  <h2>2. قصة السيناريو: ماذا يحدث على شبكة الشوارع؟</h2>
  {grid_svg}
  <div class="prof-grid">
    {topology_cards}
  </div>

  <h3>القصة خطوة بخطوة</h3>
  {scenario_svg}
  <ol>
    <li>
      يولد SUMO حركة المركبات. العدد 20 أو 40 أو 60 أو 80 أو 100 هو
      <strong>عدد مطلوب في السيناريو</strong>، وليس بالضرورة عدد المركبات
      الموجودة معاً في كل لحظة.
    </li>
    <li>
      ترسل المركبة <strong>CAM</strong> دورية تصف حركتها، أو
      <strong>DENM</strong> عندما تدعي وجود حدث أو خطر.
    </li>
    <li>
      تستقبل RSU أو مركبة شاهدة الرسالة وتكوّن ملاحظة حسية مستقلة نسبياً.
    </li>
    <li>
      يقارن الكاشف الادعاء بالملاحظة المشوشة ويولّد reason codes؛ لا يقرأ
      وسم «خبيث/سليم».
    </li>
    <li>
      تتحول الملاحظة إلى EvidenceAttestation تحمل اتجاهاً وعوامل جودة.
    </li>
    <li>
      تُوزن الأدلة، وتُمنع جذور الملاحظة المكررة من الظهور كأدلة مستقلة.
    </li>
    <li>
      إذا تحققت الجذور والمصادر والمناطق والعتبة، تصبح الحالة مؤهلة.
    </li>
    <li>
      الإلغاء النهائي يحتاج أيضاً نجاح مسار المعمارية: خادم مركزي أو نصاب موزع.
    </li>
  </ol>

  <div class="prof-warning">
    <strong>لماذا لا يكفي عدد المركبات لتفسير الرقم؟</strong>
    لأن المقام يتغير من معيار لآخر. Precision مقامها قرارات الإلغاء،
    Recall مقامها الحالات الخبيثة، Messages/Decision مقامها القرارات،
    بينما Queue موزون بالرسائل. لذلك لا توجد علاقة خطية واحدة بين 100
    مركبة وبين أي نتيجة نهائية.
  </div>
</section>

<section class="prof-section" id="prof-threat">
  <h2>3. نموذج التهديد والحالات الخبيثة</h2>
  <p>
    اختيرت 35% من المركبات كمهاجمين، فينتج تقريباً 7 و14 و21 و28 و35
    مهاجماً للكثافات الخمس. توزّعها الدالة
    <code>_evenly_spaced_indices</code> على قائمة المركبات، وتدوّر الأنواع
    السبعة للحفاظ على تمثيل متوازن.
  </p>

  {attack_html}

  <h3>قدرات المهاجم وحدودها</h3>
  <div class="prof-grid">
    {card("يستطيع",
      "<ul><li>تغيير الموقع أو السرعة المبلّغ عنها.</li>"
      "<li>إعادة رسالة قديمة.</li><li>إغراق المراقب.</li>"
      "<li>إرسال DENM كاذبة.</li><li>العبث بصلاحية الشهادة.</li></ul>")}
    {card("لا يُفترض أنه يستطيع",
      "<ul><li>تغيير Ground Truth المخزن للتقييم.</li>"
      "<li>تغيير مفتاح CRN لدليل موجود.</li>"
      "<li>تزوير رمز نصاب 3/4 وحده.</li>"
      "<li>تحويل نسخ RSU المقروءة إلى مدققين موقّعين.</li></ul>")}
    {card("العقد البيزنطية",
      "<p>النموذج الموزع يستخدم أربعة مدققين ويتحمل عقدة بيزنطية واحدة "
      "f=1، ولذلك يحتاج 2f+1=3 أصوات.</p>")}
  </div>
</section>

<section class="prof-section" id="prof-detection">
  <h2>4. كيف اكتُشف السلوك الخبيث؟</h2>
  {detection_svg}

  {table(
      ["الاختبار", "الشرط البرمجي", "ما الذي يعنيه؟"],
      [
          ("الموقع", "الخطأ > 20 m", "الفرق بين الموقع المبلّغ والملاحظة الحسية."),
          ("السرعة", "الخطأ > 5 m/s", "عدم اتساق السرعة مع الملاحظة."),
          ("إعادة nonce", "شوهد سابقاً", "دليل على إعادة استخدام هوية رسالة."),
          ("عمر الإعادة", "العمر > 2.5 s", "الرسالة أقدم من الحد المقبول."),
          ("الإغراق", ">3 رسائل/ث لدى المراقب", "عداد محلي لكل مراقب ومركبة."),
          ("DENM كاذبة", "التسارع المرصود > −3 m/s²", "لا يوجد تباطؤ فيزيائي متوافق مع ادعاء الخطر."),
          ("حداثة الدليل", "F=exp(−age/12)", "ينخفض وزن الدليل كلما تقادم."),
      ]
  )}

  <div class="prof-ok">
    الكاشف Label-blind: يقارن رسالة V2X بملاحظة حسية مولدة عند الاستقبال.
    حقول SUMO الحقيقية تُستخدم في طبقة محاكاة الحساس ثم في التقييم، وليست
    مدخلاً مباشراً إلى قرار الكشف.
  </div>
</section>

<section class="prof-section" id="prof-weighting">
  <h2>5. الأوزان: من أين جاءت وكيف تعمل؟</h2>
  {weight_svg}

  <div class="prof-equation">
    wᵢ = Vᵢ × Cᵢ<sup>αC</sup> × ρᵢ<sup>αρ</sup> ×
    Fᵢ<sup>αF</sup> × Qᵢ<sup>αQ</sup> × ηᵢ<sup>αη</sup>
  </div>

  {weights_html}

  <h3>مثال عددي قابل للتتبع</h3>
  <p>
    إذا كان C=0.90 وρ=0.85 وF=0.95 وQ=0.98 وη=0.92 وكانت الصلاحية V=1،
    فإن تطبيق الأسس المجمدة يعطي وزناً تقريبياً:
    <strong>{weights_example:.6f}</strong>.
    هذه ليست قيمة مأخوذة من حالة بعينها، بل مثال تعليمي يوضح الحساب.
    إذا أصبحت V=0 يصبح الوزن صفراً مهما كانت بقية العوامل.
  </p>

  <h3>منع تضخيم الأدلة</h3>
  <p>
    تُجمع التقارير بحسب <code>observation_root_id</code>. يؤخذ أقوى تقرير
    مؤيد وأقوى تقرير معارض، ويسهم الجذر بالفرق المطلق بينهما. لذلك لا تستطيع
    عدة نسخ مشتقة من الملاحظة نفسها أن تتنكر كعدة شهود مستقلين.
  </p>

  <div class="prof-equation">
    M<sup>+</sup>=Σ−ln(1−w<sub>support</sub>) &nbsp;&nbsp;
    M<sup>−</sup>=Σ−ln(1−w<sub>oppose</sub>)
    <br>
    D=1+M<sup>+</sup>+λM<sup>−</sup>
    <br>
    Support=M<sup>+</sup>/D &nbsp;&nbsp;
    Opposition=M<sup>−</sup>/D
  </div>

  <h3>شروط التأهيل</h3>
  {qualification_html}

  <h3>كيف اختيرت الأوزان؟</h3>
  <ul>
    <li>فُحص 1,202 مرشحاً.</li>
    <li>بذور التطوير: 1001، 1002، 1004، 1005، 1006، 1008، 1009، 1010.</li>
    <li>بذور الحجز Holdout: 1003 و1007.</li>
    <li>استخدم GroupKFold حتى خمس طيات، و200 إعادة اختيار Bootstrap.</li>
    <li>أُجري اضطراب محلي وإزالة للعوامل وPermutation Importance.</li>
    <li>كانت القيود Recall≥0.95 وFRR≤0.05 في أسوأ طية ومنظور أدلة.</li>
  </ul>

  <div class="prof-limit">
    <strong>selection_feasible=false:</strong>
    لم يحقق أي مرشح الشرطين معاً في جميع حالات أسوأ طية × منظور أدلة.
    لذلك اختير أفضل مرشح وفق ترتيب مسبق، ثم جُمّدت أوزانه قبل حملة الكثافة.
    لا يجوز وصفها بأنها أوزان مثالية أو أنها حققت كل القيود.
  </div>
</section>

<section class="prof-section" id="prof-protocols">
  <h2>6. البروتوكولان: المركزي والموزع</h2>
  {architecture_svg}

  <div class="prof-grid">
    {card("المركزي المتاح دائماً",
      "<p><code>availability=1.0</code>. يعزل أثر الإتاحة، لكنه يبقي النقل "
      "والطابور وأربعة عمال معالجة وزمن خدمة 12 ms وسعة 500.</p>")}
    {card("المركزي التشغيلي",
      "<p><code>availability=0.995</code>. يضيف محفز "
      "<code>central_server_unavailable</code>. هو افتراض نموذجي لا قياس "
      "إتاحة خادم إنتاجي.</p>")}
    {card("الموزع",
      "<p>المنسق هو أول مراقب أو يُحدد بالهاش. دليله المحلي لا يدفع قفزة "
      "RSU_EVIDENCE_EXCHANGE، أما الأدلة البعيدة فتُجمع في حزمة.</p>")}
    {card("PBFT المحاكى",
      "<p>أربعة مدققين، f=1، نصاب 3/4، ثم نسخ السجل إلى المدققين ونسخ "
      "قراءة إلى ست RSUs. هو نموذج محاكاة وليس تنفيذ PBFT إنتاجياً.</p>")}
  </div>
</section>

<section class="prof-section" id="prof-crn">
  <h2>7. لماذا المقارنة عادلة؟</h2>
  {crn_svg}
  <p>
    يشتق نموذج النقل سحب كل محاولة من:
    <code>SHA256(evidence_crn_seed | random_key | attempt)</code>.
    ويكون <code>random_key</code> مرتبطاً بمعرف EvidenceAttestation.
    لذلك يحصل الدليل المشترك على سحب loss وjitter وretry نفسه في البنيتين.
  </p>
  <p>
    رسائل PBFT ونسخ السجل والكاش لها تيارها الخاص، فلا تستهلك رقماً من
    مولد عشوائي تسلسلي يغيّر مصير الدليل التالي. بقيت الطوابير ومسار
    المنسق وإعادة التأهيل مستقلة لأنها جزء من المعمارية المراد قياسها.
  </p>
</section>

<section class="prof-section" id="prof-design">
  <h2>8. تصميم التجربة: ماذا تعني الأعداد؟</h2>
  <div class="prof-equation">
    4 طبولوجيات × 5 كثافات × 10 بذور = 200 أثر SUMO
    <br>
    200 أثر × 3 تشغيلات معمارية = 600 تشغيل
  </div>

  {table(
      ["المستوى", "تعريفه", "لماذا لا يُخلط بغيره؟"],
      [
          ("المركبة الاسمية", "مركبة مولدة في ملف السيناريو", "قد لا تكون كل المركبات نشطة معاً."),
          ("الحالة", "تدفق ثقة مرتبط بمركبة/بذرة", "ليست رسالة واحدة."),
          ("رسالة V2X", "CAM أو DENM أو نسخة Flood", "قد تولد عدة ملاحظات."),
          ("حدث كشف", "ملاحظة صادرة من RSU أو شاهد", "قد توجد أحداث كثيرة للرسالة."),
          ("جذر ملاحظة", "مصدر استقلال العد", "النسخ التابعة لا تعد شهوداً جدد."),
          ("قرار", "النتيجة النهائية لحالة", "هو مقام Messages/Decision وBytes/Decision."),
          ("خلية إحصائية", "Topology×Vehicle Count", "تضم عشر بذور مقترنة."),
      ]
  )}

  {causal_svg}
</section>

<section class="prof-section" id="prof-metrics">
  <h2>9. لماذا اختير كل معيار وكيف يُقرأ؟</h2>
  {metric_html}
  <div class="prof-warning">
    لا يمكن إعطاء «سبب وحيد» لكل منزلة عشرية. نستطيع تحديد كيفية الحساب،
    والمكونات المباشرة، والآليات المعمارية المعزولة. أما تقلب البذور
    والتغطية والتوقيت ومزيج الأدلة فيُعرض كمحددات محتملة لا كسبب مثبت منفرد.
  </div>
</section>

{topology_sections}

<section class="prof-section" id="prof-comparison">
  <h2>14. المقارنة الجامعة بين الطبولوجيات</h2>
  {overall_topology_table}
  <p>
    Intersection ولّدت أعلى رسائل وبايتات لكل قرار في الموزع، وهو متسق
    وصفياً مع كثافة أحداث الكشف وتعدد العلاقات في التقاطع. لكن لا يجوز
    إعلان أن «شكل التقاطع» سبب النتيجة وحده، لأن السيناريوهات تختلف أيضاً
    في الآثار والتغطية والتوقيت والحالات المكتملة.
  </p>
  <p>
    Smoke وحدها احتوت ثلاث نقاط تعادل ضمن 0–200 ms. في Corridor وIntersection
    وGrid بقيت جميع النقاط فوق 200 ms، لذلك هي استقراء نموذجي وليست نتائج
    مجربة داخل sweep.
  </p>
</section>

<section class="prof-section" id="prof-cases">
  <h2>15. التفسير المحافظ للـ17 والـ34 حالة</h2>

  {table(
      ["المقارنة", "المشترك", "الاختلافات", "Distributed-only", "Central-only", "الاتفاق"],
      [
          ("الموزع مقابل المركزي المتاح دائماً", "70,791", "17", "6", "11", "99.975986%"),
          ("الموزع مقابل المركزي التشغيلي", "70,791", "51", "40", "11", "99.927957%"),
      ]
  )}

  <h3>الحالات الـ34 الإضافية</h3>
  <p>
    الفرق 51−17=34. ارتبطت هذه الحالات تحديداً بمحفز
    <code>central_server_unavailable</code>: لم يدخل الدليل في مسار
    التأهيل المركزي بسبب فشل الإتاحة، بينما لا تعتمد البنية الموزعة على
    الخادم المركزي نفسه. هذا يعزل أثر الإتاحة النموذجي، لكنه لا يثبت نسبة
    تعطل لخادم حقيقي.
  </p>

  <h3>الحالات الـ17 المتبقية</h3>
  <p>
    بقيت مع availability=1.0، ولذلك ليست نتيجة عدم إتاحة الخادم.
    تفسيرها المحافظ أنها حالات حدّية في وصول الأدلة ومسارات المعمارية:
    المنسق في الموزع يستقبل دليله محلياً، بينما الأدلة الأخرى تمر بالنقل؛
    وكل مدقق يعيد التأهيل. هذا اختلاف معماري حقيقي، لكن لا يجوز اختزاله
    كله في عامل واحد دون تجربة Ablation مخصصة.
  </p>

  <div class="prof-ok">
    فرق MCC المجمّع يساوي 0.000395 فقط:
    0.761556 للمركزي مقابل 0.761161 للموزع. النتيجة الصحيحة هي الحفاظ
    التقريبي على القرار الأمني، لا تفوق دقة الموزع.
  </div>
</section>

<section class="prof-section" id="prof-communication">
  <h2>16. لماذا رسائل الموزع أقل لكن بايتاته أكثر؟</h2>
  {table(
      ["البنية", "الرسائل", "البايتات", "بايت/رسالة", "Queue موزون", "PDR"],
      [
          ("المركزي", "3,181,388", "2,239,697,152", "704.00", "6,308.74 ms", "0.980136"),
          ("الموزع", "2,521,234", "2,649,744,576", "1,050.97", "5,295.26 ms", "0.980244"),
      ]
  )}
  <p>
    الموزع خفّض عدد الرسائل بنسبة 20.75% لكنه رفع البايتات 18.31%.
    المتوسط 1,050.97 بايت/رسالة مقابل 704.00؛ والسبب المباشر أن الموزع
    يجمع أدلة متعددة داخل <code>VPUFT_EVIDENCE_BUNDLE</code> بمتوسط يقارب
    47,121 بايت، إضافة إلى PBFT والنسخ.
  </p>
  <p>
    Queue المعتمد موزون بعدد رسائل كل تشغيلة عبر 200 تشغيلة.
    في الموزع شكّلت <code>RSU_EVIDENCE_EXCHANGE</code> نحو 90.8% من
    الرسائل. المتوسط البسيط غير الموزون لأنواع الرسائل يعطي 808.67 ms
    فقط مقابل 5,295.26 ms الموزون، ولذلك يعطي صورة مضللة عن الرسالة النموذجية.
  </p>
</section>

<section class="prof-section" id="prof-cache">
  <h2>17. V2V وTrust Cache وتحليل TTL</h2>
  {cache_svg}
  <p>
    يحمل <code>QuorumTrustToken</code> الاسم المستعار وحالة الثقة ووقت
    الإصدار والانتهاء وارتفاع السجل وهاش نقطة التحقق ومعرف القرار وتواقيع
    النصاب. تستطيع RSUs الست الإجابة من نسخ قراءة، لكنها لا تستطيع منفردة
    إنشاء رمز يحتاج تواقيع 3/4.
  </p>
  {cache_html}
  <p>
    عند TTL=0 لا توجد إصابة كاش، فيكون متوسط التفويض 16.921 ms والحمل
    1,437.66 بايت/تفاعل. عند TTL=30 ترتفع الإصابة إلى 81.853% وينخفض
    الزمن إلى 3.289 ms والبايتات إلى 260.87، لكن قبول الثقة القديمة يرتفع
    إلى 4.9659%.
  </p>
  <p>
    القيم مخرجات نموذج الكاش. كلفة الحصول على تواقيع النصاب 3/4 تظهر في
    مسار Cache Miss أو Expiry، ولا تُعاد في مسار Cache Hit المحلي البالغ
    0.25 ms. اكتشاف Anomaly يبطل الإدخال ويفرض Refresh.
  </p>
  <div class="prof-warning">
    فائدة V2V هنا هي الاستفادة من رمز ثقة موقّع لدى جار متصل وفق أثر SUMO؛
    ليست إعادة تصويت على الثقة، ولا تسمح للمركبة الجارة بصنع رمز جديد.
  </div>
</section>

<section class="prof-section" id="prof-statistics">
  <h2>18. الاستدلال الإحصائي وحدوده</h2>
  <ul>
    <li>Wilcoxon للعينات المقترنة عبر عشر بذور داخل كل خلية.</li>
    <li>Bootstrap CI لعدم اليقين في الفروق المقترنة.</li>
    <li>Holm داخل كل Comparator×Metric عبر 20 خلية.</li>
    <li>24 عائلة = مقارنان × 12 معياراً.</li>
  </ul>
  <div class="prof-equation">
    p<sub>raw,min</sub> = 2 / 2<sup>10</sup> = 0.001953125
    <br>
    p<sub>Holm</sub> = 20 × 0.001953125 = 0.0390625
  </div>
  <p>
    0.0390625 هي الحد الأدنى المطلق الممكن هنا، وتحتاج اتفاق فروق البذور
    العشر كلها في الاتجاه نفسه. لذلك لا توجد بين النتائج الدالة درجات
    معدلة وسطية. بقي التحليل Post-hoc Supplementary/Exploratory.
  </p>
</section>

<section class="prof-section" id="prof-novelty">
  <h2>19. أين تكمن ميزة V-PUFT؟</h2>
  <div class="prof-grid">
    {card("ثقة مقيدة بالأدلة",
      "<p>القرار لا يعتمد سمعة عددية مجردة؛ يحتاج أدلة صالحة ومصادر وجذوراً "
      "ومناطق وحداً أدنى للقوة.</p>")}
    {card("مقاومة تضخيم الشهادات",
      "<p>العد على مستوى observation_root_id يمنع تحويل النسخ المشتقة إلى "
      "شهود مستقلين.</p>")}
    {card("مقارنة معمارية مقترنة",
      "<p>CRN يربط مصير الدليل نفسه في المركزي والموزع، فتُعزى الفروق "
      "الباقية للمسار المعماري بدرجة أقوى.</p>")}
    {card("مقايضة كمية",
      "<p>لم تكتف الدراسة بالدقة؛ قاست P95 والرسائل والبايتات والطابور "
      "والموارد ونقاط التعادل.</p>")}
    {card("كاش موقع بنصاب",
      "<p>يفصل بين سرعة الإصابة وخطر قبول الثقة القديمة، مع إبطال عند "
      "الشذوذ وتواقيع 3/4.</p>")}
    {card("صدق حدود الادعاء",
      "<p>تفصل صراحةً بين المجال المختبر والاستقراء، وبين المحاكاة والقياس "
      "الميداني، وبين الإلهام وإعادة التنفيذ.</p>")}
  </div>
  <p>
    المقارنة مع Yang وKhelifi وMalik وBLAME وAyobi وYan وAhmed هي مقارنة
    نطاق ومساهمة. لا نقارن الأرقام مباشرة لأن البيانات والعتاد والهجمات
    وإعدادات الاتصال مختلفة.
  </p>
</section>

<section class="prof-section" id="prof-traceability">
  <h2>20. خريطة تتبّع الأرقام إلى الشفرة والبيانات</h2>
  {traceability_html}
</section>

<section class="prof-section" id="prof-claims">
  <h2>21. الادعاءات المسموحة والممنوعة</h2>
  <div class="prof-grid">
    {card("مسموح",
      "<ul><li>اتفاق 99.975986% تحت CRN.</li>"
      "<li>حفاظ تقريبي على التصنيف.</li>"
      "<li>خفض الرسائل 20.75% وزيادة البايتات 18.31%.</li>"
      "<li>ثلاث نقاط تعادل فريدة داخل 0–200 ms.</li>"
      "<li>مرونة نموذجية تجاه central_server_unavailable.</li></ul>",
      "prof-ok")}
    {card("ممنوع",
      "<ul><li>الموزع أدق أو أفضل دائماً.</li>"
      "<li>البلوكتشين حسّن التصنيف بذاته.</li>"
      "<li>167.80 ms عتبة عامة.</li>"
      "<li>النتائج قياسات ميدانية أو إنتاجية.</li>"
      "<li>شكل الطريق سبب كل فرق.</li>"
      "<li>تنفيذ TRS أو مخطط Ahmed حرفياً.</li>"
      "<li>تحويل Holm الاستكشافي إلى تأكيدي.</li></ul>",
      "prof-limit")}
  </div>
</section>

<section class="prof-section" id="prof-references">
  <h2>22. المراجع الفنية والمنهجية</h2>
  {references_html}
</section>

</main>
</div>
"""

body_match = re.search(
    r"(?is)(<body\b[^>]*>)(.*)(</body>)",
    old_html
)

if not body_match:
    raise SystemExit("Could not locate the body of the approved HTML.")

original_body = body_match.group(2)

appendix = f"""
<details class="prof-old-report" open>
  <summary>
    الملحق الرقمي: التقرير العددي المعتمد كاملاً
    — 30 جدولاً و16 رسماً أصلياً
  </summary>
  <div class="prof-footnote">
    هذا الجزء هو محتوى الملف المعتمد كما هو، ويُحفظ لضمان عدم ضياع أي
    جدول أو رسم أو حاشية سبق تدقيقها.
  </div>
  {original_body}
</details>
"""

new_html = (
    old_html[:body_match.start()]
    + body_match.group(1)
    + deep_html
    + appendix
    + body_match.group(3)
    + old_html[body_match.end():]
)

new_html = re.sub(
    r"(?is)<title>.*?</title>",
    "<title>V-PUFT — الفصل الخامس الدفاعي الشامل</title>",
    new_html,
    count=1
)

if "</head>" not in new_html:
    raise SystemExit("Could not locate </head>.")

new_html = new_html.replace("</head>", CSS + "\n</head>", 1)

required_material = [
    "central_server_unavailable",
    "selection_feasible=false",
    "RSU_EVIDENCE_EXCHANGE",
    "VPUFT_EVIDENCE_BUNDLE",
    "0.0390625",
    "808.67",
    "90.8%",
    "3/4",
    "166.85",
    "189.19",
    "140.37",
    "2,521,234",
    "3,181,388",
    "2,649,744,576",
    "2,239,697,152",
    "macro",
    "Pooled",
    "Post-hoc Supplementary/Exploratory",
]

missing = [
    item for item in required_material
    if item.lower() not in new_html.lower()
]

if missing:
    raise SystemExit(f"Required material missing: {missing}")

old_images = len(re.findall(r"(?i)<img\b", old_html))
new_images = len(re.findall(r"(?i)<img\b", new_html))
old_tables = len(re.findall(r"(?i)<table\b", old_html))
new_tables = len(re.findall(r"(?i)<table\b", new_html))
new_svgs = len(re.findall(r"(?i)<svg\b", new_html))

if new_images != old_images:
    raise SystemExit(
        f"Embedded image count changed: {old_images} -> {new_images}"
    )

if new_tables <= old_tables:
    raise SystemExit(
        f"Expected additional explanatory tables: {old_tables} -> {new_tables}"
    )

if new_svgs < 8:
    raise SystemExit(f"Expected at least 8 SVG diagrams, found {new_svgs}")

NEW.write_text(new_html, encoding="utf-8")

if sha256(OLD.read_bytes()).hexdigest() != old_sha:
    raise SystemExit("STOP: approved old HTML changed unexpectedly.")

new_sha = sha256(NEW.read_bytes()).hexdigest()

print("SUCCESS — PROFESSORIAL DEFENSE DOCUMENT GENERATED")
print(f"Old file: {OLD}")
print(f"New file: {NEW}")
print(f"Old SHA-256: {old_sha}")
print(f"New SHA-256: {new_sha}")
print(f"Old size: {OLD.stat().st_size:,} bytes")
print(f"New size: {NEW.stat().st_size:,} bytes")
print(f"Embedded images preserved: {new_images}")
print(f"Tables: {old_tables} -> {new_tables}")
print(f"New SVG diagrams: {new_svgs}")
print(f"Topology analyses: {len(TOPOLOGIES)}")
print("The approved old HTML was not modified.")
