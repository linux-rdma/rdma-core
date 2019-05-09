.. Common text to describe the node name map file.

NODE NAME MAP FILE FORMAT
-------------------------

The node name map is used to specify user friendly names for nodes in the
output.  GUIDs are used to perform the lookup.

This functionality is provided by the opensm-libs package.  See **opensm(8)**
for the file location for your installation.

**Generically:**

::

   # comment
   <guid> "<name>"

**Example:**

::

   # IB1
   # Line cards
   0x0008f104003f125c "IB1 (Rack 11 slot 1   ) ISR9288/ISR9096 Voltaire sLB-24D"
   0x0008f104003f125d "IB1 (Rack 11 slot 1   ) ISR9288/ISR9096 Voltaire sLB-24D"
   0x0008f104003f10d2 "IB1 (Rack 11 slot 2   ) ISR9288/ISR9096 Voltaire sLB-24D"
   0x0008f104003f10d3 "IB1 (Rack 11 slot 2   ) ISR9288/ISR9096 Voltaire sLB-24D"
   0x0008f104003f10bf "IB1 (Rack 11 slot 12  ) ISR9288/ISR9096 Voltaire sLB-24D"
   
   # Spines
   0x0008f10400400e2d "IB1 (Rack 11 spine 1   ) ISR9288 Voltaire sFB-12D"
   0x0008f10400400e2e "IB1 (Rack 11 spine 1   ) ISR9288 Voltaire sFB-12D"
   0x0008f10400400e2f "IB1 (Rack 11 spine 1   ) ISR9288 Voltaire sFB-12D"
   0x0008f10400400e31 "IB1 (Rack 11 spine 2   ) ISR9288 Voltaire sFB-12D"
   0x0008f10400400e32 "IB1 (Rack 11 spine 2   ) ISR9288 Voltaire sFB-12D"
   
   # GUID   Node Name
   0x0008f10400411a08 "SW1  (Rack  3) ISR9024 Voltaire 9024D"
   0x0008f10400411a28 "SW2  (Rack  3) ISR9024 Voltaire 9024D"
   0x0008f10400411a34 "SW3  (Rack  3) ISR9024 Voltaire 9024D"
   0x0008f104004119d0 "SW4  (Rack  3) ISR9024 Voltaire 9024D"

