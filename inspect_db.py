import sys
from app import create_app, db
from sqlalchemy import inspect

app = create_app()

with app.app_context():
    inspector = inspect(db.engine)
    tables = inspector.get_table_names()
    print('=== Tables in the database ===')
    for t in tables:
        print(f'- {t}')
    print('\n=== Columns and foreign keys ===')
    for t in tables:
        print(f'\nTable: {t}')
        cols = inspector.get_columns(t)
        for col in cols:
            print(f"  column: {col['name']} ({col['type']}) nullable={col['nullable']}")
        fkeys = inspector.get_foreign_keys(t)
        for fk in fkeys:
            print(f"  foreign key: {fk['constrained_columns']} -> {fk['referred_table']}.{fk['referred_columns']}")
    # Verify models can be queried
    from app.models.user import User
    from app.models.scan import Scan
    print('\n=== Sample queries ===')
    print('User count:', User.query.count())
    print('Scan count:', Scan.query.count())
    sys.exit(0)
