import { Component, Input, Output, ViewChild, EventEmitter, OnChanges, SimpleChanges, Inject } from 'ng-metadata/core';


@Component({
  selector: 'corConfirmDialogBetter',
  templateUrl: '/static/js/directives/ui/cor-confirm-dialog/cor-confirm-dialog.component.html',
  legacy: {
    transclude: true,
  }
})
export class CorConfirmDialogComponent implements OnChanges {
  @Input('@') public dialogTitle: string;
  @Input('@') public dialogActionTitle: string;
  @Input('<') public dialogForm: any;
  @Input('@') public dialogButtonClass: string;
  @Input('<') public dialogContext: any;

  @Output() public dialogAction = new EventEmitter<DialogAction>();

  @ViewChild('.modal') private modal: ng.IAugmentedJQuery;

  private working = false;

  private performAction(): void {
    this.working = true;
    this.dialogAction.emit({
      info: this.dialogContext,
      callback: () => this.hide(),
    });
  }

  private show(): void {
    if (this.dialogForm) {
      this.dialogForm.$setPristine();
    }

    this.working = false;
    this.modal.modal({});
  }

  private hide(): void {
    this.modal.modal('hide');
  }

  public ngOnChanges(changes: SimpleChanges): void {
    if ('dialogContext' in changes && changes.dialogContext.currentValue !== null) {
      this.show();
    }
  }
}

export type DialogAction = {
  info: any;
  callback: (result?: any) => void;
};
